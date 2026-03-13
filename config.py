"""
配置文件模块：统一管理SSH代理的配置参数
"""

import os
import json
import logging

import constants

logger = logging.getLogger(__name__)


# 默认配置
DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "listen_port": 18080,
    "sshd_host": "127.0.0.1",
    "sshd_port": 8022,
    "max_connections": constants.MAX_CONNECTIONS,
    "connection_timeout": 300,
    "log_scan_interval": 5,
    "sshd_log_path": constants.DEFAULT_SSHD_LOG_PATH,
    "failures_to_ban": constants.MAX_FAILURES,
    "ban_duration": constants.DEFAULT_BAN_DURATION,
    "failure_window": constants.FAILURE_WINDOW,
    "last_position": 0
}


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
            logger.info("创建配置目录: %s", parent_dir)
            os.makedirs(parent_dir, exist_ok=True)
            
        return True
    except (OSError, PermissionError) as e:
        logger.error("创建目录失败 %s: %s", parent_dir, e)
        return False


def load_config(config_file=constants.CONFIG_PATH, config_dict=None):
    """
    加载配置
    
    Args:
        config_file: 配置文件路径
        config_dict: 配置字典
    
    Returns:
        配置字典
    """
    config = DEFAULT_CONFIG.copy()
    
    # 从文件加载配置
    if config_file:
        try:
            # 确保配置文件目录存在
            if not ensure_file_path(config_file):
                logger.warning("无法创建配置文件目录: %s", config_file)
            elif os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    config.update(file_config)
                    logger.info("从文件加载配置: %s", config_file)
        except (FileNotFoundError, json.JSONDecodeError, OSError, IOError) as e:
            logger.error("加载配置文件失败 %s: %s", config_file, e)
    
    # 从字典更新配置
    if config_dict:
        config.update(config_dict)
    
    return config


def save_config(config, config_file=constants.CONFIG_PATH):
    """
    保存配置到文件
    
    Args:
        config: 配置字典
        config_file: 配置文件路径
        
    Returns:
        bool: 是否成功
    """
    try:
        # 确保配置文件目录存在
        if not ensure_file_path(config_file):
            logger.error("无法创建配置文件目录: %s", config_file)
            return False
            
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info("配置已保存到: %s", config_file)
        return True
    except (OSError, IOError, TypeError) as e:
        logger.error("保存配置文件失败 %s: %s", config_file, e)
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
    
    if config.get("last_position", -1) < 0:
        return False, "日志扫描位置必须大于等于0"
    
    return True, "配置有效"
