"""
连接管理器：管理SSH连接状态和端口映射
"""

import logging
import threading
import time
from collections import defaultdict

logger = logging.getLogger(__name__)


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
                logger.warning("连接数达到上限: %s", self.max_connections)
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
                "添加连接 #%s: %s:%s -> 本地端口 %s",
                connection_id, client_info['ip'], client_info['port'], local_port
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
                    "移除连接 #%s: %s:%s, 持续时间: %.1fs, 流量: %s字节",
                    conn['conn_id'], client_info['ip'], client_info['port'],
                    duration, bytes_total
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
                logger.info("需要断开IP %s 的 %s 个连接", ip, len(threads_to_disconnect))

                # 记录要断开的连接
                for thread_id in threads_to_disconnect:
                    conn = self.active_connections[thread_id]
                    logger.info("标记连接 #%s 为断开", conn['conn_id'])

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
                        # 这里只是从管理中移除
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
                            "清理超时连接 #%s: %s:%s",
                            conn['conn_id'], conn['client_info']['ip'], conn['client_info']['port']
                        )

                if to_remove:
                    logger.info("清理了 %s 个超时连接", len(to_remove))

            except (OSError, RuntimeError) as e:
                logger.error("清理超时连接时出错: %s", e)
