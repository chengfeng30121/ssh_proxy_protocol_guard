#!/usr/bin/env python3
"""
Proxy Protocol调试工具
"""

import socket
from datetime import datetime


def analyze_proxy_protocol(data):
    """分析数据是否包含Proxy Protocol"""

    print("\n=== Proxy Protocol分析 ===")

    if len(data) < 12:
        print(f"数据不足12字节: {len(data)}字节")
        return False

    # 检查Proxy Protocol v2签名
    signature = data[:12]
    expected_v2 = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

    print(f"前12字节(hex): {signature.hex()}")
    print(f"期望v2签名(hex): {expected_v2.hex()}")

    if signature == expected_v2:
        print("✓ 检测到Proxy Protocol v2签名")
        return True

    # 检查Proxy Protocol v1
    if signature.startswith(b"PROXY "):
        print("✓ 检测到Proxy Protocol v1")
        return True

    # 尝试分析可能的格式
    print("× 不是标准的Proxy Protocol签名")

    # 显示ASCII表示
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in signature)
    print(f"ASCII表示: {ascii_repr}")

    return False


def start_debug_server(port=18080):
    """启动调试服务器"""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)

    print(f"[*] 调试服务器启动在 0.0.0.0:{port}")
    print("[*] 等待连接...")

    connection_count = 0

    while True:
        client_sock, client_addr = server.accept()
        connection_count += 1

        print(f"\n{'='*60}")
        print(f"连接 #{connection_count} 来自: {client_addr}")
        print(f"时间: {datetime.now()}")

        try:
            # 设置超时
            client_sock.settimeout(5.0)

            # 读取前64字节
            data = client_sock.recv(64)

            if not data:
                print("没有接收到数据")
                client_sock.close()
                continue

            print(f"接收到 {len(data)} 字节数据")

            # 显示原始数据
            print("\n--- 原始数据 (十六进制) ---")
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"{i:04x}: {hex_str:<48} {ascii_str}")

            # 分析Proxy Protocol
            is_pp = analyze_proxy_protocol(data)

            if is_pp and len(data) >= 16:
                # 尝试解析更多信息
                print("\n--- Proxy Protocol详细信息 ---")

                # 版本/命令
                version_command = data[12]
                version = (version_command >> 4) & 0x0F
                command = version_command & 0x0F
                print(f"版本: {version}, 命令: {command} (0x{version_command:02x})")

                if len(data) >= 14:
                    # 地址族/协议
                    family_protocol = data[13]
                    address_family = (family_protocol >> 4) & 0x0F
                    transport_protocol = family_protocol & 0x0F
                    print(
                        f"地址族: 0x{address_family:x} ({address_family}), 传输协议: {transport_protocol}"
                    )

            # 保存数据到文件
            filename = f"pp_debug_{connection_count:03d}.bin"
            with open(filename, "wb") as f:
                f.write(data)
            print(f"\n数据已保存到: {filename}")

        except socket.timeout:
            print("接收数据超时")
        except Exception as e:
            print(f"处理连接时出错: {e}")
        finally:
            client_sock.close()
            print(f"{'='*60}")


if __name__ == "__main__":
    start_debug_server(18080)
