"""
Flask 应用入口。

启动方式（在项目根目录）：
    python -m app.main
"""
import os
import sys

# 兼容：无论从项目根还是 app 目录执行，都能正确找到包
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

from flask import Flask, send_from_directory
from flask_cors import CORS

from app.api.routes import api_bp
from config import Config

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')
CORS(app)

app.register_blueprint(api_bp)


@app.route('/')
def index():
    """返回前端页面。"""
    return send_from_directory(STATIC_DIR, 'index.html')


@app.route('/<path:path>')
def static_files(path):
    """返回静态资源（css / js 等）。"""
    return send_from_directory(STATIC_DIR, path)


if __name__ == '__main__':
    print(" * Wazuh 规则可视化启动中...")
    print(f" * Wazuh 服务器: {Config.WAZUH_HOST}:{Config.WAZUH_PORT}")
    print(f" * 前端地址: http://localhost:{Config.FLASK_PORT}")
    app.run(host='0.0.0.0', port=Config.FLASK_PORT, debug=Config.FLASK_DEBUG)
