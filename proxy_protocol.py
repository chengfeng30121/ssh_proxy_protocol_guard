"""
Proxy Protocol解析器：支持Proxy Protocol v1和v2协议解析
"""

import socket
import struct
import logging

logger = logging.getLogger(__name__)


class ProxyProtocolParser:
    """Proxy Protocol v2解析器"""

    SIGNATURE_V2 = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

    @staticmethod
    def debug_header(client_sock):
        """调试Proxy Protocol头部"""
        try:
            # 偷看前32字节
            data = client_sock.recv(32, socket.MSG_PEEK)
            if len(data) >= 16:
                logger.debug("前16字节(hex): %s", data[:16].hex())

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

                        logger.debug("版本: %s, 命令: %s", version, command)
                        logger.debug(
                            "地址族: 0x%s, 协议: %s", format(address_family, 'x'), transport_protocol
                        )
                        logger.debug("地址长度: %s", addr_len)

                        return True
                    logger.debug("不是Proxy Protocol v2签名: %s", signature.hex())

            return False
        except (socket.error, OSError) as e:
            logger.error("调试Proxy Protocol头部时出错: %s", e)
            return False

    @staticmethod
    def _parse_ipv4_address(addr_data):
        """解析IPv4地址"""
        if len(addr_data) >= 12:
            src_addr = socket.inet_ntoa(addr_data[0:4])
            dst_addr = socket.inet_ntoa(addr_data[4:8])
            src_port = struct.unpack("!H", addr_data[8:10])[0]
            dst_port = struct.unpack("!H", addr_data[10:12])[0]

            logger.debug(
                "Proxy Protocol v2 (TCP/IPv4): %s:%s -> %s:%s",
                src_addr, src_port, dst_addr, dst_port
            )
            return src_addr, src_port
        logger.warning("IPv4地址数据不足: %s字节", len(addr_data))
        return None, None

    @staticmethod
    def _parse_ipv6_address(addr_data):
        """解析IPv6地址"""
        if len(addr_data) >= 36:
            src_addr = socket.inet_ntop(socket.AF_INET6, addr_data[0:16])
            dst_addr = socket.inet_ntop(socket.AF_INET6, addr_data[16:32])
            src_port = struct.unpack("!H", addr_data[32:34])[0]
            dst_port = struct.unpack("!H", addr_data[34:36])[0]

            logger.debug(
                "Proxy Protocol v2 (TCP/IPv6): %s:%s -> %s:%s",
                src_addr, src_port, dst_addr, dst_port
            )
            return src_addr, src_port
        logger.warning("IPv6地址数据不足: %s字节", len(addr_data))
        return None, None

    @staticmethod
    def parse_v2_from_data(client_sock, header_data):
        """从已读取的头部数据继续解析Proxy Protocol v2"""
        if len(header_data) < 16:
            logger.warning("头部数据不足16字节: %s", len(header_data))
            return None, None

        try:
            # 解析版本/命令
            version_command = header_data[12]
            version = (version_command >> 4) & 0x0F
            command = version_command & 0x0F

            logger.debug("Proxy Protocol v2: 版本=%s, 命令=%s", version, command)

            if version != 2:
                logger.warning("不支持的Proxy Protocol版本: %s", version)
                return None, None

            # command=0x01表示PROXY，0x00表示LOCAL
            if command != 0x01:
                logger.info("Proxy Protocol命令不是PROXY: %s", command)
                # 对于LOCAL命令，跳过地址信息
                addr_len = struct.unpack("!H", header_data[14:16])[0]
                if addr_len > 0:
                    client_sock.recv(addr_len)
                return None, None

            # 解析地址族/协议
            family_protocol = header_data[13]
            address_family = (family_protocol >> 4) & 0x0F
            transport_protocol = family_protocol & 0x0F

            logger.debug("地址族=0x%s, 协议=%s", format(address_family, 'x'), transport_protocol)

            # 解析地址长度
            addr_len = struct.unpack("!H", header_data[14:16])[0]
            logger.debug("地址数据长度: %s", addr_len)

            # 读取地址数据
            addr_data = b""
            if addr_len > 0:
                while len(addr_data) < addr_len:
                    chunk = client_sock.recv(addr_len - len(addr_data))
                    if not chunk:
                        logger.warning(
                            "读取地址数据时连接关闭，已读取 %s/%s 字节",
                            len(addr_data), addr_len
                        )
                        return None, None
                    addr_data += chunk

            # 根据地址族解析地址
            if address_family == 0x01:  # IPv4地址族
                if transport_protocol == 0x01:  # STREAM (TCP)
                    return ProxyProtocolParser._parse_ipv4_address(addr_data)
                logger.warning("不支持的传输协议: %s", transport_protocol)
                return None, None

            if address_family == 0x02:  # IPv6地址族
                if transport_protocol == 0x01:  # STREAM (TCP)
                    return ProxyProtocolParser._parse_ipv6_address(addr_data)
                logger.warning("不支持的传输协议: %s", transport_protocol)
                return None, None

            logger.warning(
                "不支持的地址族: 0x%s (transport: %s)",
                format(address_family, 'x'), transport_protocol
            )
            return None, None

        except (socket.error, OSError, struct.error) as e:
            logger.error("解析Proxy Protocol v2失败: %s", e)
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
            logger.debug("Proxy Protocol v1行: %s", line)

            # 检查是否是PROXY协议
            if not line.startswith("PROXY "):
                return None, None

            # 解析PROXY行
            parts = line.split()
            if len(parts) >= 6:
                src_ip = parts[2]
                src_port = int(parts[4])

                logger.debug(
                    "Proxy Protocol v1: %s:%s -> %s:%s",
                    src_ip, src_port, parts[3], int(parts[5])
                )
                return src_ip, src_port

        except (socket.error, OSError, ValueError, UnicodeDecodeError) as e:
            logger.error("解析Proxy Protocol v1失败: %s", e)

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

            if data.startswith(b"PROXY "):
                logger.debug("检测到Proxy Protocol v1，尝试解析...")
                # 消费偷看的数据
                client_sock.recv(16)
                # 重新读取完整行
                return ProxyProtocolParser.parse_v1(client_sock)

            logger.debug("未检测到Proxy Protocol，使用连接地址")
            return None, None
        except (socket.error, OSError) as e:
            logger.error("检查Proxy Protocol时出错: %s", e)
            return None, None
