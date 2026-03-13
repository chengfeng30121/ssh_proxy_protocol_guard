"""
IP封禁管理器：支持IP封禁、解封和失败记录管理
"""

import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

import constants

logger = logging.getLogger(__name__)


def ensure_file_path(path):
    """确保文件路径存在，如果不存在则创建父目录"""
    try:
        if not path:
            return False
            
        parent_dir = os.path.dirname(path)
        if not parent_dir:
            return True
            
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            
        return True
    except (OSError, PermissionError) as e:
        logger.error("创建目录失败 %s: %s", parent_dir, e)
        return False


class BanManager:
    """封禁管理器 - 支持自动解封"""

    def __init__(self, ban_duration=3600):
        self.ban_duration = ban_duration
        # 格式: {ip: {"block_until": timestamp, "reason": str, "banned_at": timestamp}}
        self.blacklist = {}
        self.failure_count = defaultdict(
            lambda: deque(maxlen=10)
        )
        # 端口失败记录，用于避免同一个端口的多次失败重复计数
        self.port_failures = {}  # port: timestamp
        self.lock = threading.Lock()
        self.max_failures = 5
        self.failure_window = 600  # 10分钟窗口
        self.port_window = 300  # 5分钟内同一个端口的失败只计数一次

        # 加载已保存的黑名单
        self.load_blacklist()

        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def load_blacklist(self):
        """加载黑名单"""
        blacklist_file = constants.BLACKLIST_FILE
        try:
            if os.path.exists(blacklist_file):
                with open(blacklist_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    # 转换时间戳
                    for ip, info in loaded.items():
                        info["block_until"] = float(info["block_until"])
                        info["banned_at"] = float(info["banned_at"])
                    self.blacklist = loaded

                    # 清理过期的封禁
                    now = time.time()
                    expired = [
                        ip
                        for ip, info in self.blacklist.items()
                        if info.get("block_until", 0) <= now
                    ]

                    for ip in expired:
                        del self.blacklist[ip]

                    if expired:
                        logger.info("加载时清理了 %s 个过期封禁", len(expired))
                        self.save_blacklist()

                logger.info("已加载 %s 个未过期的封禁", len(self.blacklist))
        except (json.JSONDecodeError, OSError, IOError) as e:
            logger.error("加载黑名单失败: %s", e)

    def save_blacklist(self):
        """保存黑名单"""
        blacklist_file = constants.BLACKLIST_FILE
        try:
            # 确保目录存在
            if not ensure_file_path(blacklist_file):
                logger.error("无法创建黑名单文件目录")
                return
                
            with open(blacklist_file, "w", encoding="utf-8") as f:
                json.dump(self.blacklist, f, indent=2, ensure_ascii=False)
        except (OSError, IOError) as e:
            logger.error("保存黑名单失败: %s", e)

    def is_banned(self, ip):
        """检查IP是否被封禁"""
        with self.lock:
            if ip not in self.blacklist:
                return False

            ban_info = self.blacklist[ip]
            block_until = ban_info.get("block_until", 0)

            # 检查封禁是否过期
            if time.time() > block_until:
                logger.info("IP %s 封禁已过期，自动解封", ip)
                del self.blacklist[ip]
                self.save_blacklist()
                return False

            return True

    def ban_ip(self, ip, duration=None, reason="Too many failed attempts"):
        """封禁IP"""
        if duration is None:
            duration = self.ban_duration

        with self.lock:
            block_until = time.time() + duration
            self.blacklist[ip] = {
                "block_until": block_until,
                "reason": reason,
                "banned_at": time.time(),
            }

            # 清理该IP的失败记录
            if ip in self.failure_count:
                del self.failure_count[ip]

            self.save_blacklist()
            logger.warning(
                "已封禁IP %s 直到 %s，原因: %s",
                ip, datetime.fromtimestamp(block_until), reason
            )

            # 记录封禁日志
            self._log_ban_action(f"BAN {ip} for {duration}s: {reason}")

    def unban_ip(self, ip):
        """手动解封IP"""
        with self.lock:
            if ip in self.blacklist:
                del self.blacklist[ip]
                self.save_blacklist()
                logger.info("已解封IP %s", ip)

                # 记录解封日志
                self._log_ban_action(f"UNBAN {ip}")
                return True
        return False

    def _log_ban_action(self, message):
        """记录封禁/解封日志"""
        ban_log = constants.BAN_ACTIONS_LOG
        if ensure_file_path(ban_log):
            try:
                with open(ban_log, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now()} - {message}\n")
            except (OSError, IOError) as e:
                logger.error("记录封禁日志失败: %s", e)

    def _log_failure(self, ip, count):
        """记录认证失败日志"""
        failures_log = constants.AUTH_FAILURES_LOG
        if ensure_file_path(failures_log):
            try:
                with open(failures_log, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now()} - FAILURE {ip} (total: {count})\n")
            except (OSError, IOError) as e:
                logger.error("记录失败日志失败: %s", e)

    def _log_cleanup(self, count):
        """记录清理日志"""
        cleanup_log = constants.CLEANUP_LOG
        if ensure_file_path(cleanup_log):
            try:
                with open(cleanup_log, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now()} - CLEANUP {count} expired bans\n")
            except (OSError, IOError) as e:
                logger.error("记录清理日志失败: %s", e)

    def record_failure(self, ip, port):
        """
        记录认证失败，返回当前失败次数
        
        Args:
            ip: 客户端IP
            port: 客户端端口
            
        Returns:
            失败次数
        """
        with self.lock:
            now = time.time()
            
            # 检查这个端口在5分钟内是否已经记录过失败
            if port in self.port_failures:
                last_fail_time = self.port_failures[port]
                if now - last_fail_time < self.port_window:
                    # 5分钟内同一个端口的失败，不重复计数
                    failure_count = len(self.failure_count[ip])
                    logger.debug("端口 %s 在5分钟内已记录过失败，跳过计数", port)
                    return failure_count
            
            # 记录端口失败时间
            self.port_failures[port] = now
            
            # 清理过期的端口失败记录
            expired_ports = [
                p for p, t in self.port_failures.items()
                if now - t >= self.port_window
            ]
            for p in expired_ports:
                del self.port_failures[p]

            # 添加当前失败时间
            self.failure_count[ip].append(now)

            # 清理过期记录（10分钟前）
            self.failure_count[ip] = deque(
                [t for t in self.failure_count[ip] if now - t < self.failure_window],
                maxlen=10,
            )

            failure_count = len(self.failure_count[ip])

            # 记录失败日志
            self._log_failure(ip, failure_count)

            # 检查是否达到封禁阈值
            if failure_count >= self.max_failures and not self.is_banned(ip):
                self.ban_ip(ip, reason=f"{failure_count}次认证失败 (10分钟内)")
                return failure_count

            return failure_count

    def get_ban_info(self, ip):
        """获取封禁信息"""
        with self.lock:
            if ip in self.blacklist:
                info = self.blacklist[ip]
                remaining = max(0, info["block_until"] - time.time())
                return {
                    "ip": ip,
                    "reason": info["reason"],
                    "banned_at": datetime.fromtimestamp(info["banned_at"]).strftime(
                        constants.LOG_DATE_FORMAT
                    ),
                    "block_until": datetime.fromtimestamp(info["block_until"]).strftime(
                        constants.LOG_DATE_FORMAT
                    ),
                    "remaining_seconds": int(remaining),
                    "remaining_minutes": int(remaining / 60),
                }
        return None

    def get_all_bans(self):
        """获取所有封禁信息"""
        with self.lock:
            now = time.time()
            bans = []
            for ip, info in self.blacklist.items():
                remaining = max(0, info["block_until"] - now)
                bans.append(
                    {
                        "ip": ip,
                        "reason": info["reason"],
                        "banned_at": datetime.fromtimestamp(info["banned_at"]).strftime(
                            constants.LOG_DATE_FORMAT
                        ),
                        "block_until": datetime.fromtimestamp(
                            info["block_until"]
                        ).strftime(constants.LOG_DATE_FORMAT),
                        "remaining_seconds": int(remaining),
                    }
                )
            return bans

    def _cleanup_loop(self):
        """定期清理过期封禁和端口记录"""
        while True:
            time.sleep(300)  # 每5分钟清理一次
            try:
                cleaned_count = 0
                with self.lock:
                    now = time.time()
                    
                    # 清理过期封禁
                    expired = [
                        ip
                        for ip, info in self.blacklist.items()
                        if now > info["block_until"]
                    ]

                    for ip in expired:
                        del self.blacklist[ip]
                        cleaned_count += 1

                    if cleaned_count > 0:
                        logger.info("清理了 %s 个过期封禁", cleaned_count)
                        self.save_blacklist()
                        self._log_cleanup(cleaned_count)
                    
                    # 清理过期的端口失败记录
                    expired_ports = [
                        port for port, timestamp in self.port_failures.items()
                        if now - timestamp >= self.port_window
                    ]
                    for port in expired_ports:
                        del self.port_failures[port]
                        
                    if expired_ports:
                        logger.debug("清理了 %s 个过期的端口失败记录", len(expired_ports))
                        
            except (OSError, IOError) as e:
                logger.error("清理过期记录时出错: %s", e)
