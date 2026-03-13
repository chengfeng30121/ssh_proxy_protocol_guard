#!/usr/bin/env python3
"""
SSH代理：通过端口映射实现IP追踪和封禁
"""

import json
import os
import re
import select
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta


class PortMappingSSHProxy:
    def __init__(self):
        # 配置
        self.config = {
            "listen_port": 18080,  # FRP连接端口
            "sshd_host": "127.0.0.1",  # sshd地址
            "sshd_port": 8022,  # sshd端口
            "max_connections": 25,  # 最大并发连接
            "connection_timeout": 300,  # 连接超时（秒）
            # 封禁配置
            "max_failures": 5,  # 最大失败次数
            "failure_window": 600,  # 失败计数窗口（秒）
            "ban_duration": 3600,  # 封禁时长（秒）
            # 日志配置
            "sshd_log_path": "/data/data/com.termux/files/usr/var/auth.log",
            "log_scan_interval": 5,  # 日志扫描间隔（秒）
        }

        # 数据结构
        self.port_mapping = {}  # 本地端口 -> 客户端信息
        self.active_connections = {}  # 线程ID -> 连接信息
        self.failure_count = defaultdict(
            lambda: deque(maxlen=10)
        )  # IP -> 失败时间戳队列
        self.blacklist = set()  # 黑名单IP
        self.connection_count = 0  # 当前连接数

        # 线程锁
        self.lock = threading.Lock()

        # 加载黑名单
        self.load_blacklist()

    def load_blacklist(self):
        """加载黑名单"""
        try:
            with open("blacklist.txt", "r") as f:
                self.blacklist = set(line.strip() for line in f)
                print(f"[*] 已加载 {len(self.blacklist)} 个黑名单IP")
        except FileNotFoundError:
            self.blacklist = set()

    def save_blacklist(self):
        """保存黑名单"""
        with open("blacklist.txt", "w") as f:
            for ip in self.blacklist:
                f.write(f"{ip}\n")
        print(f"[*] 已保存 {len(self.blacklist)} 个黑名单IP到黑名单")

    def add_to_blacklist(self, ip):
        """添加IP到黑名单"""
        with self.lock:
            if ip not in self.blacklist:
                self.blacklist.add(ip)
                self.save_blacklist()
                print(f"[!] 已将IP {ip} 加入黑名单")

                # 记录日志
                with open("block_actions.log", "a") as f:
                    f.write(f"{datetime.now()} - BLOCK {ip}\n")

    def is_ip_blocked(self, ip):
        """检查IP是否被封禁"""
        with self.lock:
            return ip in self.blacklist

    def record_failure(self, ip):
        """记录认证失败"""
        with self.lock:
            now = time.time()
            self.failure_count[ip].append(now)

            # 清理过期记录
            while (
                self.failure_count[ip]
                and now - self.failure_count[ip][0] > self.config["failure_window"]
            ):
                self.failure_count[ip].popleft()

            failures = len(self.failure_count[ip])

            # 检查是否达到封禁阈值
            if failures >= self.config["max_failures"]:
                self.add_to_blacklist(ip)

            return failures

    def parse_proxy_protocol(self, client_sock):
        """解析Proxy Protocol获取真实IP"""
        try:
            # 读取签名
            signature = client_sock.recv(12)
            if len(signature) < 12:
                return None

            # 检查Proxy Protocol v2签名
            if signature == b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a":
                # 读取版本和命令
                version_command = client_sock.recv(1)[0]
                version = version_command >> 4

                if version != 2:
                    return None

                # 读取地址族和协议
                family_protocol = client_sock.recv(1)[0]
                address_family = family_protocol >> 4

                # 读取长度
                length_bytes = client_sock.recv(2)
                length = int.from_bytes(length_bytes, "big")

                # 读取地址数据
                addr_data = client_sock.recv(length)

                if address_family == 0x11:  # IPv4
                    src_addr = socket.inet_ntoa(addr_data[0:4])
                    src_port = int.from_bytes(addr_data[8:10], "big")
                    return src_addr, src_port

        except Exception as e:
            print(f"[!] 解析Proxy Protocol失败: {e}")

        return None

    def create_sshd_connection(self):
        """创建到sshd的连接，返回socket和本地端口"""
        try:
            # 创建socket
            sshd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sshd_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # 绑定到随机端口
            sshd_sock.bind(("0.0.0.0", 0))

            # 获取本地端口
            local_port = sshd_sock.getsockname()[1]

            # 连接到sshd
            sshd_sock.connect((self.config["sshd_host"], self.config["sshd_port"]))
            sshd_sock.setblocking(0)  # 非阻塞模式

            return sshd_sock, local_port

        except Exception as e:
            print(f"[!] 创建sshd连接失败: {e}")
            return None, None

    def forward_connection(self, client_sock, sshd_sock, client_info):
        """转发客户端和sshd之间的数据"""
        try:
            # 设置非阻塞
            client_sock.setblocking(0)

            # 获取线程ID用于记录
            thread_id = threading.get_ident()

            with self.lock:
                self.active_connections[thread_id] = {
                    "client_ip": client_info["ip"],
                    "client_port": client_info["port"],
                    "sshd_port": client_info["sshd_port"],
                    "start_time": time.time(),
                }

            # 使用select进行双向转发
            while True:
                # 检查超时
                if (
                    time.time() - client_info["start_time"]
                    > self.config["connection_timeout"]
                ):
                    print(f"[!] 连接超时: {client_info['ip']}:{client_info['port']}")
                    break

                # 检查IP是否被封禁
                if self.is_ip_blocked(client_info["ip"]):
                    print(f"[!] 连接中断: IP {client_info['ip']} 已被封禁")
                    break

                # 使用select等待数据
                rlist, _, xlist = select.select(
                    [client_sock, sshd_sock], [], [client_sock, sshd_sock], 1
                )

                if xlist:
                    break

                for sock in rlist:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return

                        if sock is client_sock:
                            sshd_sock.sendall(data)
                        else:
                            client_sock.sendall(data)

                    except (socket.error, BlockingIOError):
                        continue

        except Exception as e:
            print(f"[!] 转发数据时出错: {e}")

        finally:
            # 清理资源
            with self.lock:
                if thread_id in self.active_connections:
                    del self.active_connections[thread_id]

            # 从端口映射中移除
            with self.lock:
                if client_info["sshd_port"] in self.port_mapping:
                    del self.port_mapping[client_info["sshd_port"]]

            client_sock.close()
            sshd_sock.close()

            # 减少连接计数
            with self.lock:
                self.connection_count -= 1

    def handle_client(self, client_sock, client_addr):
        """处理客户端连接"""
        try:
            # 1. 检查并发连接数
            with self.lock:
                if self.connection_count >= self.config["max_connections"]:
                    print(f"[!] 连接数达到上限，拒绝连接: {client_addr}")
                    client_sock.close()
                    return
                self.connection_count += 1

            # 2. 解析Proxy Protocol获取真实IP
            proxy_result = self.parse_proxy_protocol(client_sock)

            if proxy_result:
                real_ip, real_port = proxy_result
            else:
                # 如果不是Proxy Protocol，使用连接地址
                real_ip, real_port = client_addr

            print(f"[+] 新连接: {real_ip}:{real_port}")

            # 3. 检查IP是否被封禁
            if self.is_ip_blocked(real_ip):
                print(f"[!] 拒绝封禁IP的连接: {real_ip}")
                client_sock.send(b"Connection refused: Your IP has been blocked.\n")
                client_sock.close()

                with self.lock:
                    self.connection_count -= 1
                return

            # 4. 创建到sshd的连接
            sshd_sock, sshd_port = self.create_sshd_connection()
            if not sshd_sock:
                client_sock.close()

                with self.lock:
                    self.connection_count -= 1
                return

            print(f"[*] 端口映射: {real_ip}:{real_port} -> 127.0.0.1:{sshd_port}")

            # 5. 记录端口映射
            client_info = {
                "ip": real_ip,
                "port": real_port,
                "sshd_port": sshd_port,
                "start_time": time.time(),
            }

            with self.lock:
                self.port_mapping[sshd_port] = client_info

            # 6. 开始转发
            self.forward_connection(client_sock, sshd_sock, client_info)

        except Exception as e:
            print(f"[!] 处理客户端连接时出错: {e}")
            client_sock.close()

            with self.lock:
                self.connection_count -= 1

    def monitor_sshd_logs(self):
        """监控sshd日志，检测认证失败"""
        print(f"[*] 开始监控SSH日志: {self.config['sshd_log_path']}")

        # 如果日志文件不存在，创建它
        if not os.path.exists(self.config["sshd_log_path"]):
            open(self.config["sshd_log_path"], "a").close()

        # 记录上次读取位置
        last_position = os.path.getsize(self.config["sshd_log_path"])

        # 失败日志模式
        failure_patterns = [
            r"Failed password for .* from ([\d\.]+) port (\d+)",
            r"Invalid user .* from ([\d\.]+) port (\d+)",
            r"Connection closed by authenticating user .* ([\d\.]+) port (\d+)",
        ]

        while True:
            try:
                # 检查日志文件大小
                current_size = os.path.getsize(self.config["sshd_log_path"])

                if current_size < last_position:
                    # 日志被截断或轮转
                    last_position = 0

                if current_size > last_position:
                    # 读取新日志
                    with open(self.config["sshd_log_path"], "r") as f:
                        f.seek(last_position)
                        new_lines = f.readlines()
                        last_position = f.tell()

                    # 处理新日志行
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue

                        # 匹配失败模式
                        for pattern in failure_patterns:
                            match = re.search(pattern, line)
                            if match:
                                source_ip = match.group(1)
                                source_port = int(match.group(2))

                                # 记录日志
                                with open("auth_failures.log", "a") as f:
                                    f.write(f"{datetime.now()} - {line}\n")

                                # 检查端口映射
                                with self.lock:
                                    if source_port in self.port_mapping:
                                        client_info = self.port_mapping[source_port]
                                        real_ip = client_info["ip"]

                                        print(
                                            f"[!] 认证失败: 端口 {source_port} -> IP {real_ip}"
                                        )

                                        # 记录失败次数
                                        failures = self.record_failure(real_ip)
                                        print(f"[!] IP {real_ip} 失败 {failures} 次")

                                        # 如果封禁了IP，断开对应连接
                                        if self.is_ip_blocked(real_ip):
                                            # 查找并断开这个IP的所有连接
                                            self.disconnect_ip(real_ip)

                # 定期清理旧的端口映射
                self.cleanup_old_mappings()

            except Exception as e:
                print(f"[!] 监控日志时出错: {e}")

            # 休眠
            time.sleep(self.config["log_scan_interval"])

    def disconnect_ip(self, ip):
        """断开指定IP的所有连接"""
        with self.lock:
            # 查找活跃连接
            connections_to_close = []
            for thread_id, conn_info in self.active_connections.items():
                if conn_info["client_ip"] == ip:
                    connections_to_close.append(thread_id)

            # 这里无法直接关闭线程的socket，但可以标记为需要关闭
            # 实际应用中可能需要更复杂的机制
            print(f"[!] 需要断开IP {ip} 的 {len(connections_to_close)} 个连接")

            # 从端口映射中移除
            ports_to_remove = []
            for port, client_info in self.port_mapping.items():
                if client_info["ip"] == ip:
                    ports_to_remove.append(port)

            for port in ports_to_remove:
                del self.port_mapping[port]

    def cleanup_old_mappings(self):
        """清理旧的端口映射"""
        with self.lock:
            now = time.time()
            ports_to_remove = []

            for port, client_info in self.port_mapping.items():
                if now - client_info["start_time"] > self.config["connection_timeout"]:
                    ports_to_remove.append(port)

            for port in ports_to_remove:
                del self.port_mapping[port]

            if ports_to_remove:
                print(f"[*] 清理了 {len(ports_to_remove)} 个旧的端口映射")

    def start_log_monitor(self):
        """启动日志监控线程"""
        monitor_thread = threading.Thread(target=self.monitor_sshd_logs, daemon=True)
        monitor_thread.start()
        return monitor_thread

    def start_server(self):
        """启动代理服务器"""
        # 创建监听socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", self.config["listen_port"]))
        server.listen(10)

        print(f"[*] SSH代理启动在 127.0.0.1:{self.config['listen_port']}")
        print(f"[*] 最大连接数: {self.config['max_connections']}")
        print(f"[*] 监控日志: {self.config['sshd_log_path']}")

        # 启动日志监控
        self.start_log_monitor()

        try:
            while True:
                # 接受新连接
                client_sock, client_addr = server.accept()

                # 在新线程中处理连接
                thread = threading.Thread(
                    target=self.handle_client, args=(client_sock, client_addr)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            print("\n[*] 正在关闭服务器...")
        finally:
            server.close()

            # 保存黑名单
            self.save_blacklist()

            # 保存最后的状态
            with open("proxy_state.json", "w") as f:
                state = {
                    "port_mapping": {str(k): v for k, v in self.port_mapping.items()},
                    "blacklist": list(self.blacklist),
                    "failure_count": {
                        k: list(v) for k, v in self.failure_count.items()
                    },
                }
                json.dump(state, f, indent=2)


def main():
    proxy = PortMappingSSHProxy()
    proxy.start_server()


if __name__ == "__main__":
    main()
