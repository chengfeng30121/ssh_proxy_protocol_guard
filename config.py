"""
配置文件模块：统一管理SSH代理的配置参数，并将运行时状态分离到独立文件
"""

import os
import json

import constants
from constants import ensure_file_path

from cfpackages.logger_formatter import get_logger

logger = get_logger(__name__, constants.DEFAULT_LOG_LEVEL)


# 默认配置（不含任何运行时状态）
DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "listen_port": 18022,
    "sshd_host": "127.0.0.1",
    "sshd_port": 8022,
    "max_connections": constants.MAX_CONNECTIONS,
    "connection_timeout": 300,
    "log_scan_interval": 5,
    "sshd_log_path": constants.DEFAULT_SSHD_LOG_PATH,
    "failures_to_ban": constants.MAX_FAILURES,
    "ban_duration": constants.DEFAULT_BAN_DURATION,
    "failure_window": constants.FAILURE_WINDOW,
}

# 运行时状态文件路径
STATE_FILE = "SSH_Proxy/state.json"

# 配置文件注释
CONFIG_HELP = {
    "_comment": "SSH Proxy Protocol Guard 配置文件。修改后重启生效。",
    "listen_host": "代理监听地址",
    "listen_port": "代理监听端口",
    "sshd_host": "目标SSHD地址",
    "sshd_port": "目标SSHD端口",
    "max_connections": "最大并发连接数",
    "connection_timeout": "连接超时（秒）",
    "log_scan_interval": "日志扫描间隔（秒）",
    "sshd_log_path": "SSHD日志文件路径",
    "failures_to_ban": "触发封禁的失败次数",
    "ban_duration": "封禁时长（秒）",
    "failure_window": "失败计数窗口（秒）",
}


def load_config(config_file=constants.CONFIG_PATH, config_dict=None):
    """
    加载配置（从文件 + 可选的字典），返回完整配置字典。
    如果配置文件不存在，自动创建包含帮助注释的默认配置文件。
    配置文件中的未知键会被忽略并警告。
    """
    config = DEFAULT_CONFIG.copy()

    if config_file:
        try:
            if not ensure_file_path(config_file):
                logger.warning("无法创建配置文件目录: %s", config_file)
            elif not os.path.exists(config_file):
                # 自动创建默认配置文件
                save_config(DEFAULT_CONFIG, config_file)
                logger.info("已创建默认配置文件: %s", config_file)
            else:
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)

                # 移除注释字段，只合并预定义键
                file_config.pop("_comment", None)
                unknown_keys = set(file_config.keys()) - set(DEFAULT_CONFIG.keys())
                if unknown_keys:
                    logger.warning(
                        "配置文件中有未知的键，已忽略: %s",
                        ", ".join(sorted(unknown_keys)),
                    )
                # 只更新合法的配置项
                for key in DEFAULT_CONFIG:
                    if key in file_config:
                        config[key] = file_config[key]

                logger.info("从文件加载配置: %s", config_file)
        except (FileNotFoundError, json.JSONDecodeError, OSError, IOError) as e:
            logger.error("加载配置文件失败 %s: %s，使用默认配置", config_file, e)
            config = DEFAULT_CONFIG.copy()

    # 用传入的字典覆盖（如果有）
    if config_dict:
        for key in DEFAULT_CONFIG:
            if key in config_dict:
                config[key] = config_dict[key]

    return config


def save_config(config, config_file=constants.CONFIG_PATH):
    """
    保存配置到文件。只保存 DEFAULT_CONFIG 中定义的键，避免写入运行时状态。
    add_help=True 时会在顶部添加注释信息。
    """
    try:
        if not ensure_file_path(config_file):
            logger.error("无法创建配置文件目录: %s", config_file)
            return False

        # 只导出合法的配置项
        export = {k: config.get(k, DEFAULT_CONFIG[k]) for k in DEFAULT_CONFIG}
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(export, f, indent=2, ensure_ascii=False)

        logger.info("配置已保存到: %s", config_file)
        return True
    except (OSError, IOError, TypeError) as e:
        logger.error("保存配置文件失败 %s: %s", config_file, e)
        return False


def load_state():
    """加载运行时状态（目前只有 last_position）"""
    state = {"last_position": 0}
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                state.update(loaded)
    except (json.JSONDecodeError, OSError, IOError) as e:
        logger.error("加载状态文件失败: %s，使用默认状态", e)
    return state


def save_state(state):
    """保存运行时状态到独立文件"""
    try:
        if not ensure_file_path(STATE_FILE):
            logger.error("无法创建状态文件目录")
            return False
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        return True
    except (OSError, IOError, TypeError) as e:
        logger.error("保存状态文件失败: %s", e)
        return False


def validate_config(config):
    """
    验证配置有效性
    
    Args:
        config: 配置字典
    
    Returns:
        (bool, str): (是否有效, 错误信息)
    """
    # 端口范围检查
    if not (1 <= config.get("listen_port", 0) <= 65535):
        return False, "监听端口必须在1-65535范围内"
    
    if not (1 <= config.get("sshd_port", 0) <= 65535):
        return False, "SSH端口必须在1-65535范围内"
    
    # 连接数检查
    if config.get("max_connections", 0) <= 0:
        return False, "最大连接数必须大于0"
    
    # 超时时间检查
    if config.get("connection_timeout", 0) <= 0:
        return False, "连接超时必须大于0"
    
    # 扫描间隔检查
    if config.get("log_scan_interval", 0) <= 0:
        return False, "日志扫描间隔必须大于0"
    
    # 失败次数检查
    if config.get("failures_to_ban", 0) <= 0:
        return False, "封禁失败次数阈值必须大于0"
    
    # 封禁时长检查
    if config.get("ban_duration", 0) <= 0:
        return False, "封禁时长必须大于0"
    
    # 失败窗口检查
    if config.get("failure_window", 0) <= 0:
        return False, "失败计数窗口必须大于0"
    
    return True, "配置有效"
