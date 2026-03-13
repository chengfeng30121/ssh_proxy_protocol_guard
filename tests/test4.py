#!/usr/bin/env python3
"""
修复版的SSH代理：修正Proxy Protocol解析和封禁逻辑
"""

import errno
import json
import logging
import os
import re
import select
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("ssh_proxy.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class BanManager:
    """封禁管理器 - 支持自动解封"""

    def __init__(self, ban_duration=3600):
        self.ban_duration = ban_duration  # 默认封禁1小时
        # 格式: {ip: {"block_until": timestamp, "reason": str, "banned_at": timestamp}}
        self.blacklist = {}
        self.failure_count = defaultdict(
            lambda: deque(maxlen=10)
        )  # IP -> 失败时间戳队列
        self.lock = threading.Lock()
        self.max_failures = 5
        self.failure_window = 600  # 10分钟窗口

        # 加载已保存的黑名单
        self.load_blacklist()

        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def load_blacklist(self):
        """加载黑名单"""
        try:
            if os.path.exists("blacklist.json"):
                with open("blacklist.json", "r") as f:
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
                        logger.info(f"加载时清理了 {len(expired)} 个过期封禁")
                        self.save_blacklist()

                logger.info(f"已加载 {len(self.blacklist)} 个未过期的封禁")
        except Exception as e:
            logger.error(f"加载黑名单失败: {e}")

    def save_blacklist(self):
        """保存黑名单"""
        try:
            with open("blacklist.json", "w") as f:
                json.dump(self.blacklist, f, indent=2)
        except Exception as e:
            logger.error(f"保存黑名单失败: {e}")

    def is_banned(self, ip):
        """检查IP是否被封禁"""
        with self.lock:
            if ip not in self.blacklist:
                return False

            ban_info = self.blacklist[ip]
            block_until = ban_info.get("block_until", 0)

            # 检查封禁是否过期
            if time.time() > block_until:
                logger.info(f"IP {ip} 封禁已过期，自动解封")
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
                f"已封禁IP {ip} 直到 {datetime.fromtimestamp(block_until)}，原因: {reason}"
            )

            # 记录封禁日志
            with open("ban_actions.log", "a") as f:
                f.write(f"{datetime.now()} - BAN {ip} for {duration}s: {reason}\n")

    def unban_ip(self, ip):
        """手动解封IP"""
        with self.lock:
            if ip in self.blacklist:
                del self.blacklist[ip]
                self.save_blacklist()
                logger.info(f"已解封IP {ip}")

                # 记录解封日志
                with open("ban_actions.log", "a") as f:
                    f.write(f"{datetime.now()} - UNBAN {ip}\n")
                return True
        return False

    def record_failure(self, ip):
        """记录认证失败，返回当前失败次数"""
        with self.lock:
            now = time.time()

            # 添加当前失败时间
            self.failure_count[ip].append(now)

            # 清理过期记录（10分钟前）
            self.failure_count[ip] = deque(
                [t for t in self.failure_count[ip] if now - t < self.failure_window],
                maxlen=10,
            )

            failure_count = len(self.failure_count[ip])

            # 记录失败日志
            with open("auth_failures.log", "a") as f:
                f.write(f"{datetime.now()} - FAILURE {ip} (total: {failure_count})\n")

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
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "block_until": datetime.fromtimestamp(info["block_until"]).strftime(
                        "%Y-%m-%d %H:%M:%S"
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
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "block_until": datetime.fromtimestamp(
                            info["block_until"]
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                        "remaining_seconds": int(remaining),
                    }
                )
            return bans

    def _cleanup_loop(self):
        """定期清理过期封禁"""
        while True:
            time.sleep(300)  # 每5分钟清理一次
            try:
                cleaned_count = 0
                with self.lock:
                    now = time.time()
                    expired = [
                        ip
                        for ip, info in self.blacklist.items()
                        if now > info["block_until"]
                    ]

                    for ip in expired:
                        del self.blacklist[ip]
                        cleaned_count += 1

                    if cleaned_count > 0:
                        logger.info(f"清理了 {cleaned_count} 个过期封禁")
                        self.save_blacklist()

                        # 记录清理日志
                        with open("cleanup.log", "a") as f:
                            f.write(
                                f"{datetime.now()} - CLEANUP {cleaned_count} expired bans\n"
                            )
            except Exception as e:
                logger.error(f"清理过期封禁时出错: {e}")


class ProxyProtocolParser:
    """Proxy Protocol v2解析器 - 修复版本"""

    SIGNATURE_V2 = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

    @staticmethod
    def debug_header(client_sock):
        """调试Proxy Protocol头部"""
        try:
            # 偷看前32字节
            data = client_sock.recv(32, socket.MSG_PEEK)
            if len(data) >= 16:
                logger.debug(f"前16字节(hex): {data[:16].hex()}")

                # 检查签名
                if len(data) >= 12:
                    signature = data[:12]
                    if signature == ProxyProtocolParser.SIGNATURE_V2:
                        logger.debug("检测到Proxy Protocol v2签名")

                        # 解析头部信息
                        version_command = data[12]
                        version = (version_command >> 4) & 0x0F
                        command = version_command & 0x0F

                        family_protocol = data[13]
                        address_family = (family_protocol >> 4) & 0x0F
                        transport_protocol = family_protocol & 0x0F

                        addr_len = struct.unpack("!H", data[14:16])[0]

                        logger.debug(f"版本: {version}, 命令: {command}")
                        logger.debug(
                            f"地址族: 0x{address_family:x}, 协议: {transport_protocol}"
                        )
                        logger.debug(f"地址长度: {addr_len}")

                        return True
                    else:
                        logger.debug(f"不是Proxy Protocol v2签名: {signature.hex()}")

            return False
        except Exception as e:
            logger.error(f"调试Proxy Protocol头部时出错: {e}")
            return False

    @staticmethod
    def parse_v2_from_data(client_sock, header_data):
        """从已读取的头部数据继续解析Proxy Protocol v2"""
        try:
            if len(header_data) < 16:
                logger.warning(f"头部数据不足16字节: {len(header_data)}")
                return None, None

            # 解析版本/命令
            version_command = header_data[12]
            version = (version_command >> 4) & 0x0F
            command = version_command & 0x0F

            logger.debug(f"Proxy Protocol v2: 版本={version}, 命令={command}")

            if version != 2:
                logger.warning(f"不支持的Proxy Protocol版本: {version}")
                return None, None

            # command=0x01表示PROXY，0x00表示LOCAL
            if command != 0x01:
                logger.info(f"Proxy Protocol命令不是PROXY: {command}")
                # 对于LOCAL命令，跳过地址信息
                family_protocol = header_data[13]
                addr_len = struct.unpack("!H", header_data[14:16])[0]

                # 跳过地址数据
                if addr_len > 0:
                    client_sock.recv(addr_len)
                return None, None

            # 解析地址族/协议
            family_protocol = header_data[13]
            fp_byte = family_protocol
            address_family = (fp_byte >> 4) & 0x0F
            transport_protocol = fp_byte & 0x0F

            logger.debug(f"地址族=0x{address_family:x}, 协议={transport_protocol}")

            # 解析地址长度
            addr_len = struct.unpack("!H", header_data[14:16])[0]
            logger.debug(f"地址数据长度: {addr_len}")

            # 读取地址数据
            addr_data = b""
            if addr_len > 0:
                while len(addr_data) < addr_len:
                    chunk = client_sock.recv(addr_len - len(addr_data))
                    if not chunk:
                        logger.warning(
                            f"读取地址数据时连接关闭，已读取 {len(addr_data)}/{addr_len} 字节"
                        )
                        return None, None
                    addr_data += chunk

            # 解析地址
            if address_family == 0x01:  # IPv4地址族
                if transport_protocol == 0x01:  # STREAM (TCP)
                    if len(addr_data) >= 12:
                        src_addr = socket.inet_ntoa(addr_data[0:4])
                        dst_addr = socket.inet_ntoa(addr_data[4:8])
                        src_port = struct.unpack("!H", addr_data[8:10])[0]
                        dst_port = struct.unpack("!H", addr_data[10:12])[0]

                        logger.debug(
                            f"Proxy Protocol v2 (TCP/IPv4): {src_addr}:{src_port} -> {dst_addr}:{dst_port}"
                        )
                        return src_addr, src_port
                    else:
                        logger.warning(f"IPv4地址数据不足: {len(addr_data)}字节")
                        return None, None
                else:
                    logger.warning(f"不支持的传输协议: {transport_protocol}")
                    return None, None

            elif address_family == 0x02:  # IPv6地址族
                if transport_protocol == 0x01:  # STREAM (TCP)
                    if len(addr_data) >= 36:
                        src_addr = socket.inet_ntop(socket.AF_INET6, addr_data[0:16])
                        dst_addr = socket.inet_ntop(socket.AF_INET6, addr_data[16:32])
                        src_port = struct.unpack("!H", addr_data[32:34])[0]
                        dst_port = struct.unpack("!H", addr_data[34:36])[0]

                        logger.debug(
                            f"Proxy Protocol v2 (TCP/IPv6): {src_addr}:{src_port} -> {dst_addr}:{dst_port}"
                        )
                        return src_addr, src_port
                    else:
                        logger.warning(f"IPv6地址数据不足: {len(addr_data)}字节")
                        return None, None
                else:
                    logger.warning(f"不支持的传输协议: {transport_protocol}")
                    return None, None
            else:
                logger.warning(
                    f"不支持的地址族: 0x{address_family:x} (transport: {transport_protocol})"
                )
                return None, None

        except Exception as e:
            logger.error(f"解析Proxy Protocol v2失败: {e}")
            return None, None

    @staticmethod
    def parse_v1(client_sock):
        """解析Proxy Protocol v1（文本协议）"""
        try:
            # 读取一行
            data = b""
            while b"\r\n" not in data:
                chunk = client_sock.recv(1)
                if not chunk:
                    break
                data += chunk

            if not data:
                return None, None

            line = data.decode("ascii", errors="ignore").strip()
            logger.debug(f"Proxy Protocol v1行: {line}")

            # 检查是否是PROXY协议
            if not line.startswith("PROXY "):
                return None, None

            # 解析PROXY行
            # 格式: PROXY TCP4 源IP 目标IP 源端口 目标端口
            parts = line.split()
            if len(parts) >= 6:
                proto = parts[1]
                src_ip = parts[2]
                dst_ip = parts[3]
                src_port = int(parts[4])
                dst_port = int(parts[5])

                logger.debug(
                    f"Proxy Protocol v1: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                return src_ip, src_port

        except Exception as e:
            logger.error(f"解析Proxy Protocol v1失败: {e}")

        return None, None

    @staticmethod
    def parse(client_sock):
        """尝试解析Proxy Protocol（先v2后v1）"""
        try:
            # 偷看前16字节
            data = client_sock.recv(16, socket.MSG_PEEK)
            if len(data) < 16:
                return None, None

            # 检查是否是v2
            if data[:12] == ProxyProtocolParser.SIGNATURE_V2:
                logger.debug("检测到Proxy Protocol v2签名，开始解析...")
                # 消费偷看的数据
                client_sock.recv(16)
                # 使用已读取的头部数据进行解析
                return ProxyProtocolParser.parse_v2_from_data(client_sock, data)
            elif data.startswith(b"PROXY "):
                logger.debug("检测到Proxy Protocol v1，尝试解析...")
                # 消费偷看的数据
                client_sock.recv(16)
                # 重新读取完整行
                return ProxyProtocolParser.parse_v1(client_sock)
            else:
                logger.debug("未检测到Proxy Protocol，使用连接地址")
                return None, None
        except Exception as e:
            logger.error(f"检查Proxy Protocol时出错: {e}")
            return None, None


class ConnectionManager:
    """连接管理器"""

    def __init__(self, max_connections=100, connection_timeout=300):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout

        # 活动连接
        self.active_connections = {}  # thread_id -> connection_info
        self.port_mapping = {}  # local_port -> client_info
        self.ip_to_ports = defaultdict(set)  # ip -> set(local_ports)

        # 统计
        self.connection_counter = 0
        self.lock = threading.Lock()

        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def add_connection(self, thread_id, client_info, local_port):
        """添加新连接"""
        with self.lock:
            if len(self.active_connections) >= self.max_connections:
                logger.warning(f"连接数达到上限: {self.max_connections}")
                return False

            connection_id = self.connection_counter
            self.connection_counter += 1

            self.active_connections[thread_id] = {
                "conn_id": connection_id,
                "client_info": client_info,
                "local_port": local_port,
                "start_time": time.time(),
                "last_activity": time.time(),
                "bytes_sent": 0,
                "bytes_received": 0,
            }

            self.port_mapping[local_port] = {
                "ip": client_info["ip"],
                "port": client_info["port"],
                "thread_id": thread_id,
                "start_time": time.time(),
                "conn_id": connection_id,
            }

            self.ip_to_ports[client_info["ip"]].add(local_port)

            logger.info(
                f"添加连接 #{connection_id}: {client_info['ip']}:{client_info['port']} -> 本地端口 {local_port}"
            )
            return True

    def update_activity(self, thread_id, sent=0, received=0):
        """更新连接活动时间"""
        with self.lock:
            if thread_id in self.active_connections:
                conn = self.active_connections[thread_id]
                conn["last_activity"] = time.time()
                conn["bytes_sent"] += sent
                conn["bytes_received"] += received

    def remove_connection(self, thread_id):
        """移除连接"""
        with self.lock:
            if thread_id in self.active_connections:
                conn = self.active_connections[thread_id]
                local_port = conn["local_port"]
                client_ip = conn["client_info"]["ip"]

                # 从端口映射中移除
                if local_port in self.port_mapping:
                    del self.port_mapping[local_port]

                # 从IP到端口的映射中移除
                if client_ip in self.ip_to_ports:
                    self.ip_to_ports[client_ip].discard(local_port)
                    if not self.ip_to_ports[client_ip]:
                        del self.ip_to_ports[client_ip]

                # 从活动连接中移除
                client_info = conn["client_info"]
                duration = time.time() - conn["start_time"]
                bytes_total = conn["bytes_sent"] + conn["bytes_received"]

                del self.active_connections[thread_id]

                logger.info(
                    f"移除连接 #{conn['conn_id']}: {client_info['ip']}:{client_info['port']}, "
                    f"持续时间: {duration:.1f}s, 流量: {bytes_total}字节"
                )

    def get_client_by_port(self, local_port):
        """通过本地端口获取客户端信息"""
        with self.lock:
            if local_port in self.port_mapping:
                return self.port_mapping[local_port]
        return None

    def get_connections_by_ip(self, ip):
        """获取指定IP的所有连接"""
        with self.lock:
            ports = self.ip_to_ports.get(ip, set())
            connections = []
            for port in ports:
                if port in self.port_mapping:
                    connections.append(self.port_mapping[port])
            return connections

    def disconnect_ip(self, ip):
        """断开指定IP的所有连接，返回需要断开的线程ID列表"""
        with self.lock:
            threads_to_disconnect = []

            for thread_id, conn in self.active_connections.items():
                if conn["client_info"]["ip"] == ip:
                    threads_to_disconnect.append(thread_id)

            if threads_to_disconnect:
                logger.info(f"需要断开IP {ip} 的 {len(threads_to_disconnect)} 个连接")

                # 记录要断开的连接
                for thread_id in threads_to_disconnect:
                    conn = self.active_connections[thread_id]
                    logger.info(f"标记连接 #{conn['conn_id']} 为断开")

            return threads_to_disconnect

    def get_stats(self):
        """获取统计信息"""
        with self.lock:
            return {
                "active_connections": len(self.active_connections),
                "port_mappings": len(self.port_mapping),
                "unique_ips": len(self.ip_to_ports),
                "connections": list(self.active_connections.values()),
            }

    def _cleanup_loop(self):
        """清理超时连接"""
        while True:
            time.sleep(60)  # 每分钟清理一次
            try:
                with self.lock:
                    now = time.time()
                    to_remove = []

                    for thread_id, conn in self.active_connections.items():
                        # 检查超时
                        if now - conn["last_activity"] > self.connection_timeout:
                            to_remove.append(thread_id)

                    for thread_id in to_remove:
                        # 这里只是从管理中移除，实际的socket需要在线程中关闭
                        conn = self.active_connections[thread_id]
                        local_port = conn["local_port"]
                        client_ip = conn["client_info"]["ip"]

                        if local_port in self.port_mapping:
                            del self.port_mapping[local_port]

                        if client_ip in self.ip_to_ports:
                            self.ip_to_ports[client_ip].discard(local_port)
                            if not self.ip_to_ports[client_ip]:
                                del self.ip_to_ports[client_ip]

                        del self.active_connections[thread_id]

                        logger.warning(
                            f"清理超时连接 #{conn['conn_id']}: {conn['client_info']['ip']}:{conn['client_info']['port']}"
                        )

                if to_remove:
                    logger.info(f"清理了 {len(to_remove)} 个超时连接")

            except Exception as e:
                logger.error(f"清理超时连接时出错: {e}")


class SSHProxy:
    """SSH代理主类 - 修复版"""

    def __init__(self, config=None):
        # 默认配置
        self.config = {
            "listen_host": "127.0.0.1",
            "listen_port": 18080,
            "sshd_host": "127.0.0.1",
            "sshd_port": 8022,
            "max_connections": 100,
            "connection_timeout": 300,
            "log_scan_interval": 5,
            "sshd_log_path": os.path.expanduser("~/.ssh/sshd.log"),
            "failures_to_ban": 5,
            "ban_duration": 3600,
            "failure_window": 600,
        }

        # 更新用户配置
        if config:
            self.config.update(config)

        # 初始化组件
        self.ban_manager = BanManager(ban_duration=self.config["ban_duration"])
        self.conn_manager = ConnectionManager(
            max_connections=self.config["max_connections"],
            connection_timeout=self.config["connection_timeout"],
        )

        # 需要断开的连接
        self.connections_to_close = set()
        self.connections_lock = threading.Lock()

        # 日志模式
        self.failure_patterns = [
            r"Failed password for .* from ([\d\.]+) port (\d+)",
            r"Invalid user .* from ([\d\.]+) port (\d+)",
            r"Connection closed by authenticating user .* ([\d\.]+) port (\d+)",
            r"error: maximum authentication attempts exceeded for .* from ([\d\.]+) port (\d+)",
            r"Received disconnect from ([\d\.]+) port (\d+):.*authfail",
        ]

        # 服务器socket
        self.server_socket = None
        self.running = False

        logger.info("SSH代理初始化完成")

    def create_sshd_connection(self):
        """创建到sshd的连接"""
        try:
            # 创建socket
            sshd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sshd_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # 绑定到随机端口（用于端口映射）
            sshd_sock.bind(("0.0.0.0", 0))

            # 获取本地端口
            local_port = sshd_sock.getsockname()[1]

            # 连接到sshd
            sshd_sock.connect((self.config["sshd_host"], self.config["sshd_port"]))

            # 设置非阻塞
            sshd_sock.setblocking(False)

            return sshd_sock, local_port

        except Exception as e:
            logger.error(f"创建sshd连接失败: {e}")
            return None, None

    def should_close_connection(self, thread_id):
        """检查连接是否需要关闭"""
        with self.connections_lock:
            return thread_id in self.connections_to_close

    def mark_connection_for_closing(self, thread_id):
        """标记连接需要关闭"""
        with self.connections_lock:
            self.connections_to_close.add(thread_id)

    def forward_connection(self, client_sock, sshd_sock, client_info, local_port):
        """转发连接数据"""
        thread_id = threading.get_ident()
        conn_id = None

        # 添加到连接管理器
        if not self.conn_manager.add_connection(thread_id, client_info, local_port):
            logger.error(f"连接数达到上限，拒绝连接: {client_info['ip']}")
            client_sock.close()
            if sshd_sock:
                sshd_sock.close()
            return

        try:
            # 设置非阻塞
            client_sock.setblocking(False)

            # 超时时间
            timeout = self.config["connection_timeout"]
            last_activity = time.time()

            # 获取连接ID用于日志
            with self.conn_manager.lock:
                if thread_id in self.conn_manager.active_connections:
                    conn_id = self.conn_manager.active_connections[thread_id].get(
                        "conn_id"
                    )

            while time.time() - last_activity < timeout:
                try:
                    # 检查是否需要关闭连接
                    if self.should_close_connection(thread_id):
                        logger.info(f"连接 #{conn_id} 被标记为关闭")
                        break

                    # 使用select等待数据
                    rlist, wlist, xlist = select.select(
                        [client_sock, sshd_sock], [], [client_sock, sshd_sock], 1.0
                    )

                    if xlist:
                        # 异常情况
                        logger.debug(f"连接 #{conn_id} 异常")
                        break

                    data_transferred = False
                    for sock in rlist:
                        try:
                            if sock is client_sock:
                                data = client_sock.recv(4096)
                                if data:
                                    sshd_sock.sendall(data)
                                    last_activity = time.time()
                                    self.conn_manager.update_activity(
                                        thread_id, sent=len(data)
                                    )
                                    data_transferred = True
                                else:
                                    # 客户端关闭连接
                                    logger.debug(f"连接 #{conn_id} 客户端关闭连接")
                                    return

                            elif sock is sshd_sock:
                                data = sshd_sock.recv(4096)
                                if data:
                                    client_sock.sendall(data)
                                    last_activity = time.time()
                                    self.conn_manager.update_activity(
                                        thread_id, received=len(data)
                                    )
                                    data_transferred = True
                                else:
                                    # sshd关闭连接
                                    logger.debug(f"连接 #{conn_id} sshd关闭连接")
                                    return

                        except BlockingIOError:
                            # 非阻塞socket没有数据，继续
                            continue
                        except ConnectionResetError:
                            logger.debug(f"连接 #{conn_id} 被重置")
                            return
                        except socket.error as e:
                            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                                continue
                            logger.debug(f"连接 #{conn_id} socket错误: {e}")
                            return

                    # 如果没有数据传输，稍微等待
                    if not data_transferred:
                        time.sleep(0.01)

                except select.error as e:
                    logger.debug(f"连接 #{conn_id} select错误: {e}")
                    break
                except Exception as e:
                    logger.error(f"连接 #{conn_id} 转发数据时出错: {e}")
                    break

            # 超时
            logger.info(f"连接 #{conn_id} 超时")

        except Exception as e:
            logger.error(f"连接 #{conn_id} 转发连接时出错: {e}")
        finally:
            # 清理资源
            try:
                client_sock.close()
            except:
                pass

            try:
                sshd_sock.close()
            except:
                pass

            # 从连接管理器移除
            self.conn_manager.remove_connection(thread_id)

            # 从关闭列表中移除
            with self.connections_lock:
                self.connections_to_close.discard(thread_id)

    def handle_client(self, client_sock, client_addr):
        """处理客户端连接"""
        try:
            # 先设置超时，避免客户端不发送数据
            client_sock.settimeout(5.0)

            # 解析Proxy Protocol
            logger.debug("开始解析Proxy Protocol...")
            real_ip, real_port = ProxyProtocolParser.parse(client_sock)

            if real_ip is None:
                # 不是Proxy Protocol，使用连接地址
                real_ip, real_port = client_addr
                logger.info(f"使用连接地址: {real_ip}:{real_port}")
            else:
                logger.info(f"解析到真实客户端: {real_ip}:{real_port}")

            # 恢复socket为非阻塞模式
            client_sock.setblocking(True)
            client_sock.settimeout(None)

            client_info = {
                "ip": real_ip,
                "port": real_port,
                "connect_time": time.time(),
            }

            # 检查IP是否被封禁
            if self.ban_manager.is_banned(real_ip):
                ban_info = self.ban_manager.get_ban_info(real_ip)
                if ban_info:
                    remaining = ban_info["remaining_seconds"]
                    logger.warning(
                        f"拒绝被封禁IP的连接: {real_ip}，剩余封禁时间: {remaining}秒"
                    )

                # 发送拒绝消息
                try:
                    client_sock.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
                    client_sock.sendall(
                        b"Connection refused: Your IP has been blocked.\r\n"
                    )
                    time.sleep(1)  # 确保消息发送
                except:
                    pass

                client_sock.close()
                return

            # 创建到sshd的连接
            sshd_sock, local_port = self.create_sshd_connection()
            if sshd_sock is None:
                logger.error(f"无法连接到sshd: {real_ip}")
                client_sock.close()
                return

            logger.info(f"端口映射: {real_ip}:{real_port} -> 127.0.0.1:{local_port}")

            # 开始转发
            self.forward_connection(client_sock, sshd_sock, client_info, local_port)

        except socket.timeout:
            logger.warning(f"连接超时: {client_addr}")
            client_sock.close()
        except Exception as e:
            logger.error(f"处理客户端连接时出错: {e}")
            try:
                client_sock.close()
            except:
                pass

    def monitor_sshd_logs(self):
        """监控sshd日志，检测认证失败"""
        log_file = self.config["sshd_log_path"]

        # 确保日志文件存在
        if not os.path.exists(log_file):
            logger.warning(f"SSH日志文件不存在: {log_file}")
            try:
                # 尝试创建目录
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                open(log_file, "a").close()
                logger.info(f"已创建日志文件: {log_file}")
            except Exception as e:
                logger.error(f"创建日志文件失败: {e}")
                return

        logger.info(f"开始监控SSH日志: {log_file}")

        # 记录上次读取位置
        last_position = 0

        while self.running:
            try:
                # 检查文件大小
                current_size = os.path.getsize(log_file)

                if current_size < last_position:
                    # 日志文件被轮转或截断
                    logger.info("检测到日志文件轮转，从头开始读取")
                    last_position = 0

                if current_size > last_position:
                    # 读取新日志
                    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        last_position = f.tell()

                    # 处理新日志行
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue

                        # 检查日志行是否包含认证失败
                        for pattern in self.failure_patterns:
                            match = re.search(pattern, line)
                            if match:
                                source_ip = match.group(1)
                                try:
                                    source_port = int(match.group(2))
                                except (ValueError, IndexError):
                                    # 有些模式可能只有一个组
                                    source_port = 0

                                logger.info(
                                    f"检测到认证失败: {source_ip}:{source_port} - {line[:100]}..."
                                )

                                # 记录到失败日志
                                with open("auth_failures.log", "a") as f:
                                    f.write(f"{datetime.now()} - {line}\n")

                                # 通过端口查找真实IP
                                client_info = self.conn_manager.get_client_by_port(
                                    source_port
                                )
                                if client_info:
                                    real_ip = client_info["ip"]

                                    # 记录失败
                                    failures = self.ban_manager.record_failure(real_ip)
                                    logger.warning(
                                        f"IP {real_ip} 认证失败，累计 {failures} 次"
                                    )

                                    # 如果被封禁，断开连接
                                    if self.ban_manager.is_banned(real_ip):
                                        logger.warning(
                                            f"IP {real_ip} 已被封禁，断开连接"
                                        )
                                        threads = self.conn_manager.disconnect_ip(
                                            real_ip
                                        )
                                        for thread_id in threads:
                                            self.mark_connection_for_closing(thread_id)
                                else:
                                    # 没有找到端口映射，可能是直接连接或连接已关闭
                                    logger.debug(f"未找到端口 {source_port} 的映射")

                # 休眠
                time.sleep(self.config["log_scan_interval"])

            except FileNotFoundError:
                logger.error(f"日志文件不存在: {log_file}")
                time.sleep(10)
            except Exception as e:
                logger.error(f"监控日志时出错: {e}")
                time.sleep(10)

    def start_log_monitor(self):
        """启动日志监控线程"""
        monitor_thread = threading.Thread(target=self.monitor_sshd_logs, daemon=True)
        monitor_thread.start()
        return monitor_thread

    def start(self):
        """启动代理服务器"""
        try:
            # 创建服务器socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(
                (self.config["listen_host"], self.config["listen_port"])
            )
            self.server_socket.listen(10)

            self.running = True

            logger.info(
                f"SSH代理启动在 {self.config['listen_host']}:{self.config['listen_port']}"
            )
            logger.info(f"转发到 {self.config['sshd_host']}:{self.config['sshd_port']}")
            logger.info(f"最大连接数: {self.config['max_connections']}")

            # 启动日志监控
            self.start_log_monitor()

            # 接受连接循环
            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    logger.debug(f"接受新连接: {client_addr}")

                    # 在新线程中处理连接
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, client_addr),
                        daemon=True,
                    )
                    thread.start()

                except KeyboardInterrupt:
                    logger.info("收到中断信号，正在关闭...")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"接受连接时出错: {e}")
                    if self.running:
                        time.sleep(1)  # 避免快速重试

        except Exception as e:
            logger.error(f"启动服务器时出错: {e}")
        finally:
            self.stop()

    def stop(self):
        """停止代理服务器"""
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
                logger.info("服务器socket已关闭")
            except:
                pass

        # 保存状态
        self.ban_manager.save_blacklist()
        logger.info("黑名单已保存")


def main():
    """主函数"""
    # 配置
    config = {
        "listen_port": 18080,
        "sshd_port": 8022,
        "max_connections": 25,
        "ban_duration": 3600,  # 封禁1小时
    }

    # 创建并启动代理
    proxy = SSHProxy(config)

    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("正在关闭代理...")
        proxy.stop()
    except Exception as e:
        logger.error(f"代理运行出错: {e}")
        proxy.stop()


if __name__ == "__main__":
    main()
