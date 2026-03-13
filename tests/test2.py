#!/usr/bin/env python3
"""
健壮的SSH代理：正确处理Proxy Protocol v2、连接管理和自动解封
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
                    # 只加载未过期的封禁
                    now = time.time()
                    for ip, info in loaded.items():
                        if info.get("block_until", 0) > now:
                            self.blacklist[ip] = info

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

    def unban_ip(self, ip):
        """手动解封IP"""
        with self.lock:
            if ip in self.blacklist:
                del self.blacklist[ip]
                self.save_blacklist()
                logger.info(f"已解封IP {ip}")
                return True
        return False

    def record_failure(self, ip):
        """记录认证失败，返回当前失败次数"""
        with self.lock:
            now = time.time()

            # 添加当前失败时间
            self.failure_count[ip].append(now)

            # 清理过期记录
            recent_failures = [
                t for t in self.failure_count[ip] if now - t < self.failure_window
            ]
            self.failure_count[ip] = deque(recent_failures, maxlen=10)

            failure_count = len(self.failure_count[ip])

            # 检查是否达到封禁阈值
            if failure_count >= self.max_failures and not self.is_banned(ip):
                self.ban_ip(ip, reason=f"失败次数: {failure_count}")

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
                    "banned_at": datetime.fromtimestamp(info["banned_at"]).isoformat(),
                    "block_until": datetime.fromtimestamp(
                        info["block_until"]
                    ).isoformat(),
                    "remaining_seconds": int(remaining),
                }
        return None

    def _cleanup_loop(self):
        """定期清理过期封禁"""
        while True:
            time.sleep(300)  # 每5分钟清理一次
            try:
                with self.lock:
                    now = time.time()
                    expired = [
                        ip
                        for ip, info in self.blacklist.items()
                        if now > info["block_until"]
                    ]

                    for ip in expired:
                        del self.blacklist[ip]

                    if expired:
                        logger.info(f"清理了 {len(expired)} 个过期封禁")
                        self.save_blacklist()
            except Exception as e:
                logger.error(f"清理过期封禁时出错: {e}")


class ProxyProtocolParser:
    """Proxy Protocol v2解析器"""

    SIGNATURE_V2 = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

    @staticmethod
    def parse_v2(client_sock):
        """解析Proxy Protocol v2"""
        try:
            # 1. 读取签名（12字节）
            signature = b""
            while len(signature) < 12:
                chunk = client_sock.recv(12 - len(signature))
                if not chunk:
                    return None, None
                signature += chunk

            if signature != ProxyProtocolParser.SIGNATURE_V2:
                # 不是v2协议，将数据放回socket缓冲区
                # 注意：socket不支持真正的unread，所以这里需要特殊处理
                # 由于我们之后会直接转发数据，这里先简单返回None
                # 实际应用中可能需要更复杂的处理
                return None, None

            # 2. 读取版本/命令（1字节）
            version_command = client_sock.recv(1)
            if not version_command:
                return None, None

            version = (version_command[0] >> 4) & 0x0F
            command = version_command[0] & 0x0F

            if version != 2:
                logger.warning(f"不支持的Proxy Protocol版本: {version}")
                return None, None

            # command=0x01表示PROXY，0x00表示LOCAL
            if command != 0x01:
                logger.info(f"Proxy Protocol命令不是PROXY: {command}")
                # 对于LOCAL命令，可以继续但返回None
                return None, None

            # 3. 读取地址族/协议（1字节）
            family_protocol = client_sock.recv(1)
            if not family_protocol:
                return None, None

            address_family = (family_protocol[0] >> 4) & 0x0F
            protocol = family_protocol[0] & 0x0F

            # 4. 读取长度（2字节，大端序）
            length_bytes = b""
            while len(length_bytes) < 2:
                chunk = client_sock.recv(2 - len(length_bytes))
                if not chunk:
                    return None, None
                length_bytes += chunk

            addr_len = struct.unpack("!H", length_bytes)[0]

            # 5. 读取地址数据
            addr_data = b""
            while len(addr_data) < addr_len:
                chunk = client_sock.recv(addr_len - len(addr_data))
                if not chunk:
                    return None, None
                addr_data += chunk

            # 6. 解析地址
            if address_family == 0x11:  # TCP over IPv4
                if len(addr_data) < 12:
                    logger.warning(f"IPv4地址数据不足: {len(addr_data)}字节")
                    return None, None

                src_addr = socket.inet_ntoa(addr_data[0:4])
                dst_addr = socket.inet_ntoa(addr_data[4:8])
                src_port = struct.unpack("!H", addr_data[8:10])[0]
                dst_port = struct.unpack("!H", addr_data[10:12])[0]

                logger.debug(
                    f"Proxy Protocol v2: {src_addr}:{src_port} -> {dst_addr}:{dst_port}"
                )
                return src_addr, src_port

            elif address_family == 0x21:  # TCP over IPv6
                if len(addr_data) < 36:
                    logger.warning(f"IPv6地址数据不足: {len(addr_data)}字节")
                    return None, None

                src_addr = socket.inet_ntop(socket.AF_INET6, addr_data[0:16])
                dst_addr = socket.inet_ntop(socket.AF_INET6, addr_data[16:32])
                src_port = struct.unpack("!H", addr_data[32:34])[0]
                dst_port = struct.unpack("!H", addr_data[34:36])[0]

                logger.debug(
                    f"Proxy Protocol v2 (IPv6): {src_addr}:{src_port} -> {dst_addr}:{dst_port}"
                )
                return src_addr, src_port
            else:
                logger.warning(f"不支持的地址族: {address_family}")
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

            # 检查是否是PROXY协议
            if not line.startswith("PROXY "):
                # 不是PROXY协议，需要将数据放回
                # 这里简化处理，返回None
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
        # 尝试v2
        result = ProxyProtocolParser.parse_v2(client_sock)
        if result[0] is not None:
            return result

        # 尝试v1
        result = ProxyProtocolParser.parse_v1(client_sock)
        if result[0] is not None:
            return result

        return None, None


class ConnectionManager:
    """连接管理器"""

    def __init__(self, max_connections=100, connection_timeout=300):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout

        # 活动连接
        self.active_connections = {}  # thread_id -> connection_info
        self.port_mapping = {}  # local_port -> client_info

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

            self.active_connections[thread_id] = {
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
            }

            logger.info(
                f"添加连接: {client_info['ip']}:{client_info['port']} -> 本地端口 {local_port}"
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

                # 从端口映射中移除
                if local_port in self.port_mapping:
                    del self.port_mapping[local_port]

                # 从活动连接中移除
                client_info = conn["client_info"]
                duration = time.time() - conn["start_time"]
                bytes_total = conn["bytes_sent"] + conn["bytes_received"]

                del self.active_connections[thread_id]

                logger.info(
                    f"移除连接: {client_info['ip']}:{client_info['port']}, "
                    f"持续时间: {duration:.1f}s, 流量: {bytes_total}字节"
                )

    def get_client_by_port(self, local_port):
        """通过本地端口获取客户端信息"""
        with self.lock:
            if local_port in self.port_mapping:
                return self.port_mapping[local_port]
        return None

    def disconnect_ip(self, ip):
        """断开指定IP的所有连接"""
        with self.lock:
            threads_to_remove = []

            for thread_id, conn in self.active_connections.items():
                if conn["client_info"]["ip"] == ip:
                    threads_to_remove.append(thread_id)

            if threads_to_remove:
                logger.info(f"需要断开IP {ip} 的 {len(threads_to_remove)} 个连接")
                # 注意：这里只是标记，实际的socket关闭需要在连接线程中处理
                return threads_to_remove

        return []

    def get_stats(self):
        """获取统计信息"""
        with self.lock:
            return {
                "active_connections": len(self.active_connections),
                "port_mappings": len(self.port_mapping),
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

                        if local_port in self.port_mapping:
                            del self.port_mapping[local_port]

                        del self.active_connections[thread_id]

                        logger.warning(
                            f"清理超时连接: {conn['client_info']['ip']}:{conn['client_info']['port']}"
                        )

                if to_remove:
                    logger.info(f"清理了 {len(to_remove)} 个超时连接")

            except Exception as e:
                logger.error(f"清理超时连接时出错: {e}")


class SSHProxy:
    """SSH代理主类"""

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

    def forward_connection(self, client_sock, sshd_sock, client_info, local_port):
        """转发连接数据"""
        thread_id = threading.get_ident()

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

            # 缓冲区
            client_buffer = b""
            sshd_buffer = b""

            while time.time() - last_activity < timeout:
                try:
                    # 使用select等待数据
                    rlist, wlist, xlist = select.select(
                        [client_sock, sshd_sock], [], [client_sock, sshd_sock], 1.0
                    )

                    if xlist:
                        # 异常情况
                        logger.debug(f"连接异常: {client_info['ip']}")
                        break

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
                                    logger.debug(f"客户端 -> sshd: {len(data)}字节")
                                else:
                                    # 客户端关闭连接
                                    logger.debug(f"客户端关闭连接: {client_info['ip']}")
                                    return

                            elif sock is sshd_sock:
                                data = sshd_sock.recv(4096)
                                if data:
                                    client_sock.sendall(data)
                                    last_activity = time.time()
                                    self.conn_manager.update_activity(
                                        thread_id, received=len(data)
                                    )
                                    logger.debug(f"sshd -> 客户端: {len(data)}字节")
                                else:
                                    # sshd关闭连接
                                    logger.debug(f"sshd关闭连接: {client_info['ip']}")
                                    return

                        except BlockingIOError:
                            # 非阻塞socket没有数据，继续
                            continue
                        except ConnectionResetError:
                            logger.debug(f"连接被重置: {client_info['ip']}")
                            return
                        except socket.error as e:
                            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                                continue
                            logger.debug(f"socket错误: {e}")
                            return

                except select.error as e:
                    logger.debug(f"select错误: {e}")
                    break
                except Exception as e:
                    logger.error(f"转发数据时出错: {e}")
                    break

            # 超时
            logger.info(f"连接超时: {client_info['ip']}:{client_info['port']}")

        except Exception as e:
            logger.error(f"转发连接时出错: {e}")
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

    def handle_client(self, client_sock, client_addr):
        """处理客户端连接"""
        try:
            # 解析Proxy Protocol
            real_ip, real_port = ProxyProtocolParser.parse(client_sock)

            if real_ip is None:
                # 不是Proxy Protocol，使用连接地址
                real_ip, real_port = client_addr

            client_info = {
                "ip": real_ip,
                "port": real_port,
                "connect_time": time.time(),
            }

            logger.info(f"新连接: {real_ip}:{real_port}")

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
                                    f"检测到认证失败: {source_ip}:{source_port} - {line}"
                                )

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
                                        # 注意：这里只是标记，实际断开需要其他机制
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
