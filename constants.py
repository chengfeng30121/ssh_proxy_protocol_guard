"""
常量定义：统一管理SSH代理中的所有常量和工具函数
"""
import logging
import os

# SSH日志正则表达式模式 — 认证失败
FAILURE_PATTERNS = [
    r"Failed password for .* from ([\d\.]+) port (\d+)",
    r"Invalid user .* from ([\d\.]+) port (\d+)",
]

# SSH日志正则表达式模式 — 认证成功
SUCCESS_PATTERNS = [
    r"Accepted password for .* from ([\d\.]+) port (\d+)",
    r"Accepted publickey for .* from ([\d\.]+) port (\d+)",
]

# 网络相关常量
DEFAULT_BUFFER_SIZE = 4096
SELECT_TIMEOUT = 1.0
CONNECTION_TIMEOUT = 2
DEFAULT_SOCKET_TIMEOUT = 30  # 30秒的默认socket超时

# 日志相关常量
if os.environ.get("loglevel", "info").lower() == "debug":
    DEFAULT_LOG_LEVEL = logging.DEBUG
else:
    DEFAULT_LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 文件相关常量
DEFAULT_SSHD_LOG_PATH = "/data/data/com.termux/files/usr/var/log/auth.log"
os.makedirs("SSH_Proxy", exist_ok=True)
BLACKLIST_FILE = "SSH_Proxy/blacklist.json"
AUTH_FAILURES_LOG = "SSH_Proxy/auth_failures.log"
BAN_ACTIONS_LOG = "SSH_Proxy/ban_actions.log"
CLEANUP_LOG = "SSH_Proxy/cleanup.log"
SSH_PROXY_LOG = "SSH_Proxy/ssh_proxy.log"
CONFIG_PATH = "SSH_Proxy/config.json"

# 安全相关常量 (默认)
DEFAULT_BAN_DURATION = 3600  # 1小时
MAX_FAILURES = 5
FAILURE_WINDOW = 600  # 10分钟
MAX_CONNECTIONS = 20


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
            return False
            
        parent_dir = os.path.dirname(path)
        if not parent_dir:
            return True
            
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            
        return True
    except (OSError, PermissionError) as e:
        # 不能导入 logger，此处只返回 False，由调用者处理日志
        return False
