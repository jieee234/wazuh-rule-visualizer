#!/usr/bin/env python3
"""
便捷启动脚本（Windows 双击即可，或 python scripts/run.py）。
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)

if __name__ == '__main__':
    from app.main import app
    from config import Config
    print(f" * Wazuh 规则可视化已启动: http://localhost:{Config.FLASK_PORT}")
    app.run(host='0.0.0.0', port=Config.FLASK_PORT, debug=Config.FLASK_DEBUG)
