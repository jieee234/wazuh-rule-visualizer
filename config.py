import os
from dotenv import load_dotenv

# 加载 .env 文件（若存在）
load_dotenv()


class Config:
    # Wazuh 服务器连接
    WAZUH_HOST = os.getenv('WAZUH_HOST', 'localhost')
    WAZUH_PORT = int(os.getenv('WAZUH_PORT', '55000'))
    WAZUH_USERNAME = os.getenv('WAZUH_USERNAME', 'wazuh')
    WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD', 'wazuh')

    # 规则拉取
    RULE_LIMIT = int(os.getenv('RULE_LIMIT', '100'))
    FETCH_ALL_RULES = os.getenv('FETCH_ALL_RULES', 'False').lower() in ('true', '1', 'yes')

    # Web 服务
    FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() in ('true', '1', 'yes')

    # 请求超时（秒）
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
