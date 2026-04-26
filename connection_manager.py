"""
连接管理器：管理SSH连接状态和端口映射
"""

import threading
import time

import constants

from cfpackages.logger_formatter import get_logger

logger = get_logger(__name__, constants.DEFAULT_LOG_LEVEL)


class ConnectionManager:
    """连接管理器"""

    def __init__(self, max_connections=100, connection_timeout=300):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout

        # 只需要一个数据结构：thread_id -> 连接信息
        self.active_connections = {}  # thread_id -> connection_info
        self.lock = threading.Lock()
        
        # 简单的端口映射（不再需要延迟清理）
        self.port_mapping = {}  # local_port -> (ip, port, thread_id)

        # 统计
        self.connection_counter = 0

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

                # 从活动连接中移除
                del self.active_connections[thread_id]
                
                # 不立即删除端口映射，但标记为关闭
                if local_port in self.port_mapping:
                    self.port_mapping[local_port]["closed"] = True
                    self.port_mapping[local_port]["closed_time"] = time.time()

                # 记录日志
                client_info = conn["client_info"]
                duration = time.time() - conn["start_time"]
                bytes_total = conn["bytes_sent"] + conn["bytes_received"]

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
            connections = []
            for info in self.port_mapping.values():
                if not info.get("closed", False) and info["ip"] == ip:
                    connections.append(info)
            return connections

    def disconnect_ip(self, ip):
        """断开指定IP的所有连接"""
        with self.lock:
            threads_to_disconnect = []

            for thread_id, conn in self.active_connections.items():
                if conn["client_info"]["ip"] == ip:
                    threads_to_disconnect.append(thread_id)

            if threads_to_disconnect:
                logger.info("标记IP %s 的 %s 个连接为待断开", ip, len(threads_to_disconnect))

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
                "connections": list(self.active_connections.values()),
            }

    def _cleanup_loop(self):
        """定期清理已关闭的连接"""
        while True:
            time.sleep(60)  # 每分钟清理一次
            try:
                with self.lock:
                    now = time.time()
                    
                    # 清理超时连接
                    to_remove = []
                    for thread_id, conn in self.active_connections.items():
                        if now - conn["last_activity"] > self.connection_timeout:
                            to_remove.append(thread_id)
    
                    for thread_id in to_remove:
                        conn = self.active_connections[thread_id]
                        local_port = conn["local_port"]
                        
                        if local_port in self.port_mapping:
                            self.port_mapping[local_port]["closed"] = True
                            self.port_mapping[local_port]["closed_time"] = time.time()
    
                        del self.active_connections[thread_id]
    
                        logger.warning(
                            "清理超时连接 #%s: %s:%s",
                            conn['conn_id'], conn['client_info']['ip'], conn['client_info']['port']
                        )
    
                    # 清理超过10分钟的已关闭端口映射
                    ports_to_remove = []
                    for port, info in self.port_mapping.items():
                        if info.get("closed", False):
                            closed_time = info.get("closed_time", 0)
                            if now - closed_time > 600:  # 10分钟
                                ports_to_remove.append(port)
                    
                    # 注意：这里原来的拼写是 ports_to_remove，现已修正
                    for port in ports_to_remove:
                        del self.port_mapping[port]
                    
                    if ports_to_remove:
                        logger.debug("清理了 %s 个已关闭的端口映射", len(ports_to_remove))
    
                if to_remove:
                    logger.info("清理了 %s 个超时连接", len(to_remove))
    
            except (OSError, RuntimeError) as e:
                logger.error("清理连接时出错: %s", e)
    