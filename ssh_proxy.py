#!/usr/bin/env python3
"""
SSH代理主程序：实现SSH连接的Proxy Protocol解析、端口映射和IP封禁功能
"""

import errno
import logging
import os
import re
import select
import socket
import threading
import time
from datetime import datetime

from proxy_protocol import ProxyProtocolParser
from connection_manager import ConnectionManager
from ban_manager import BanManager
from config import load_config, validate_config, save_config
import constants

# 配置日志
logging.basicConfig(
    level=constants.DEFAULT_LOG_LEVEL,
    format=constants.LOG_FORMAT,
    handlers=[logging.FileHandler(constants.SSH_PROXY_LOG), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def ensure_file_path(path):
    """
    确保文件路径存在，如果不存在则创建父目录
    
    Args:
        path: 文件路径
        
    Returns:
        bool: 是否成功
    """
    try:
        if not path:
            logger.error("文件路径为空")
            return False
            
        # 获取父目录
        parent_dir = os.path.dirname(path)
        if not parent_dir:
            # 没有父目录，是当前目录下的文件
            return True
            
        # 创建目录（如果不存在）
        if not os.path.exists(parent_dir):
            logger.info("创建目录: %s", parent_dir)
            os.makedirs(parent_dir, exist_ok=True)
            
        return True
    except (OSError, PermissionError) as e:
        logger.error("创建目录失败 %s: %s", parent_dir, e)
        return False


class SSHProxy:
    """SSH代理主类"""

    def __init__(self):
        # 加载配置
        self.config = load_config()
        
        # 验证配置
        is_valid, error_msg = validate_config(self.config)
        if not is_valid:
            raise ValueError(f"配置无效: {error_msg}")
        
        # 初始化组件
        self.ban_manager = BanManager(ban_duration=self.config["ban_duration"])
        self.conn_manager = ConnectionManager(
            max_connections=self.config["max_connections"],
            connection_timeout=self.config["connection_timeout"],
        )

        # 需要断开的连接
        self.connections_to_close = set()
        self.connections_lock = threading.Lock()

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

        except (socket.error, OSError) as e:
            logger.error("创建sshd连接失败: %s", e)
            return None, None

    def should_close_connection(self, thread_id):
        """检查连接是否需要关闭"""
        with self.connections_lock:
            return thread_id in self.connections_to_close

    def mark_connection_for_closing(self, thread_id):
        """标记连接需要关闭"""
        with self.connections_lock:
            self.connections_to_close.add(thread_id)

    def _handle_socket_data(self, src_sock, dst_sock, thread_id, direction):
        """处理socket数据传输"""
        try:
            data = src_sock.recv(constants.DEFAULT_BUFFER_SIZE)
            if data:
                dst_sock.sendall(data)
                if direction == "sent":
                    self.conn_manager.update_activity(thread_id, sent=len(data))
                else:
                    self.conn_manager.update_activity(thread_id, received=len(data))
                return True
            return False
        except BlockingIOError:
            return True
        except ConnectionResetError:
            return False
        except socket.error as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return True
            return False

    def forward_connection(self, client_sock, sshd_sock, client_info, local_port):
        """转发连接数据"""
        thread_id = threading.get_ident()
        conn_id = None

        # 添加到连接管理器
        if not self.conn_manager.add_connection(thread_id, client_info, local_port):
            logger.error("连接数达到上限，拒绝连接: %s", client_info['ip'])
            client_sock.close()
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
                # 检查是否需要关闭连接
                if self.should_close_connection(thread_id):
                    logger.info("连接 #%s 被标记为关闭", conn_id)
                    break

                # 使用select等待数据
                rlist, _, xlist = select.select(
                    [client_sock, sshd_sock], [], [client_sock, sshd_sock], constants.SELECT_TIMEOUT
                )

                if xlist:
                    logger.debug("连接 #%s 异常", conn_id)
                    break

                data_transferred = False
                for sock in rlist:
                    if sock is client_sock:
                        if not self._handle_socket_data(
                            client_sock, sshd_sock, thread_id, "sent"
                        ):
                            logger.debug("连接 #%s 客户端关闭连接", conn_id)
                            return
                        data_transferred = True
                    elif sock is sshd_sock:
                        if not self._handle_socket_data(
                            sshd_sock, client_sock, thread_id, "received"
                        ):
                            logger.debug("连接 #%s sshd关闭连接", conn_id)
                            return
                        data_transferred = True

                if data_transferred:
                    last_activity = time.time()
                else:
                    time.sleep(0.01)

            logger.info("连接 #%s 超时", conn_id)

        except (select.error, socket.error) as e:
            logger.error("连接 #%s 转发数据时出错: %s", conn_id, e)
        finally:
            # 清理资源
            try:
                client_sock.close()
            except (socket.error, OSError):
                pass

            try:
                sshd_sock.close()
            except (socket.error, OSError):
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
            client_sock.settimeout(constants.CONNECTION_TIMEOUT)

            # 解析Proxy Protocol
            logger.debug("开始解析Proxy Protocol...")
            real_ip, real_port = ProxyProtocolParser.parse(client_sock)

            if real_ip is None:
                # 不是Proxy Protocol，使用连接地址
                real_ip, real_port = client_addr
                logger.info("使用连接地址: %s:%s", real_ip, real_port)
            else:
                logger.info("解析到真实客户端: %s:%s", real_ip, real_port)

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
                        "拒绝被封禁IP的连接: %s，剩余封禁时间: %s秒", real_ip, remaining
                    )

                # 发送拒绝消息
                try:
                    client_sock.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
                    client_sock.sendall(
                        b"Connection refused: Your IP has been blocked.\r\n"
                    )
                    time.sleep(1)
                except (socket.error, OSError):
                    pass

                client_sock.close()
                return

            # 创建到sshd的连接
            sshd_sock, local_port = self.create_sshd_connection()
            if sshd_sock is None:
                logger.error("无法连接到sshd: %s", real_ip)
                client_sock.close()
                return

            logger.info("端口映射: %s:%s -> 127.0.0.1:%s", real_ip, real_port, local_port)

            # 开始转发
            self.forward_connection(client_sock, sshd_sock, client_info, local_port)

        except socket.timeout:
            logger.warning("连接超时: %s", client_addr)
            client_sock.close()
        except (socket.error, OSError) as e:
            logger.error("处理客户端连接时出错: %s", e)
            try:
                client_sock.close()
            except (socket.error, OSError):
                pass

    def _ensure_sshd_log_file(self, log_file):
        """确保SSH日志文件存在且可访问"""
        try:
            if not log_file:
                logger.error("SSH日志文件路径为空")
                return False
            
            # 检查是否是文件（如果已存在）
            if os.path.exists(log_file):
                if not os.path.isfile(log_file):
                    logger.error("SSH日志路径不是文件: %s", log_file)
                    return False
                return True
            
            # 确保父目录存在
            if not ensure_file_path(log_file):
                return False
            
            # 创建空文件
            with open(log_file, 'w', encoding='utf-8') as f:
                pass
            logger.info("创建SSH日志文件: %s", log_file)
            return True
            
        except (OSError, IOError, PermissionError) as e:
            logger.error("创建SSH日志文件失败 %s: %s", log_file, e)
            return False

    def monitor_sshd_logs(self):
        """监控sshd日志，检测认证失败"""
        log_file = self.config["sshd_log_path"]
        
        # 确保日志文件存在
        if not self._ensure_sshd_log_file(log_file):
            logger.error("无法访问SSH日志文件: %s", log_file)
            return

        logger.info("开始监控SSH日志: %s", log_file)

        # 记录上次读取位置
        last_position = self.config.get("last_position", 0)
        failure_patterns = constants.FAILURE_PATTERNS

        while self.running:
            try:
                # 检查文件大小
                current_size = os.path.getsize(log_file)

                if current_size < last_position:
                    logger.info("检测到日志文件轮转，从头开始读取")
                    self.config["last_position"] = 0

                if current_size > last_position:
                    # 读取新日志
                    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        self.config["last_position"] = f.tell()

                    # 处理新日志行
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue

                        # 检查日志行是否包含认证失败
                        for pattern in failure_patterns:
                            match = re.search(pattern, line)
                            if match:
                                source_ip = match.group(1)
                                try:
                                    source_port = int(match.group(2))
                                except (ValueError, IndexError):
                                    source_port = 0

                                logger.info(
                                    "检测到认证失败: %s:%s - %s...",
                                    source_ip,
                                    source_port,
                                    line[:100],
                                )

                                # 记录到失败日志
                                failures_log = constants.AUTH_FAILURES_LOG
                                if ensure_file_path(failures_log):
                                    with open(failures_log, "a", encoding="utf-8") as f:
                                        f.write(f"{datetime.now()} - {line}\n")

                                # 通过端口查找真实IP
                                client_info = self.conn_manager.get_client_by_port(
                                    source_port
                                )
                                if client_info:
                                    real_ip = client_info["ip"]

                                    # 记录失败，传递端口避免重复计数
                                    failures = self.ban_manager.record_failure(real_ip, source_port)
                                    logger.warning(
                                        "IP %s 认证失败，累计 %s 次", real_ip, failures
                                    )

                                    # 如果被封禁，断开连接
                                    if self.ban_manager.is_banned(real_ip):
                                        logger.warning(
                                            "IP %s 已被封禁，断开连接", real_ip
                                        )
                                        threads = self.conn_manager.disconnect_ip(
                                            real_ip
                                        )
                                        for thread_id in threads:
                                            self.mark_connection_for_closing(thread_id)
                                else:
                                    # 没有找到端口映射
                                    logger.debug("未找到端口 %s 的映射", source_port)

                # 休眠
                time.sleep(self.config["log_scan_interval"])

            except (FileNotFoundError, OSError, IOError) as e:
                logger.error("监控日志时出错: %s", e)
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
                "SSH代理启动在 %s:%s",
                self.config['listen_host'],
                self.config['listen_port']
            )
            logger.info("转发到 %s:%s", self.config['sshd_host'], self.config['sshd_port'])
            logger.info("最大连接数: %s", self.config['max_connections'])

            # 启动日志监控
            self.start_log_monitor()

            # 接受连接循环
            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    logger.debug("接受新连接: %s", client_addr)

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
                except (socket.error, OSError) as e:
                    logger.error("接受连接时出错: %s", e)
                    if self.running:
                        time.sleep(1)

        except (socket.error, OSError) as e:
            logger.error("启动服务器时出错: %s", e)
        finally:
            self.stop()

    def stop(self):
        """停止代理服务器"""
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
                logger.info("服务器socket已关闭")
            except (socket.error, OSError):
                pass

        # 保存状态
        self.ban_manager.save_blacklist()
        logger.info("黑名单已保存")


def main():
    """主函数"""
    # 创建并启动代理
    proxy = SSHProxy()

    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("正在关闭代理...")
        proxy.stop()
    except (socket.error, OSError) as e:
        logger.error("代理运行出错: %s", e)
        proxy.stop()
    finally:
        save_config(proxy.config)


if __name__ == "__main__":
    main()
