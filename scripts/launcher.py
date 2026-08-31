#!/usr/bin/env python3
"""
双击一键启动器。

职责：
1. 检查 Python 依赖，缺失则自动安装
2. 检测端口占用并提示
3. 延迟 3 秒自动打开默认浏览器
4. 启动 Flask 服务

由 start.bat 调用：python scripts/launcher.py
"""
import os
import socket
import subprocess
import sys
import threading
import webbrowser

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)

REQUIRED_MODULES = ['flask', 'flask_cors', 'requests', 'dotenv']


def print_banner():
    line = "=" * 50
    print(line)
    print("   Wazuh 规则依赖关系可视化工具")
    print(line)
    print()


def check_deps():
    """返回 True 表示依赖齐全。"""
    for mod in REQUIRED_MODULES:
        try:
            __import__(mod)
        except ImportError:
            return False
    return True


def install_deps():
    """安装依赖，返回是否成功。"""
    print("首次运行，正在自动安装依赖，请稍候...")
    code = subprocess.call(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        shell=False,
    )
    return code == 0


def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def open_browser_later(port):
    """3 秒后打开默认浏览器（等服务就绪）。"""
    # 隐藏测试开关：设置 SKIP_OPEN_BROWSER=1 时不打开浏览器
    if os.getenv('SKIP_OPEN_BROWSER', '').lower() in ('1', 'true', 'yes'):
        return

    def _open():
        try:
            # 用 127.0.0.1 打开，规避部分环境 localhost 解析慢的问题
            webbrowser.open(f"http://127.0.0.1:{port}")
            print(f"已在浏览器中打开 http://127.0.0.1:{port}")
        except Exception as e:
            print(f"[提示] 无法自动打开浏览器，请手动访问 http://127.0.0.1:{port}（{e}）")
    threading.Timer(3.0, _open).start()


def main():
    print_banner()

    # 1) 依赖
    if not check_deps():
        if not install_deps():
            print()
            print("[错误] 依赖安装失败，请检查网络后重新双击启动。")
            input("按回车键关闭窗口...")
            return 1

    # 2) 配置与端口
    from config import Config
    port = Config.FLASK_PORT
    if port_in_use(port):
        print(f"[警告] 端口 {port} 已被占用（可能服务已在运行？）。")
        print("       请先关闭占用端口的程序，或修改 .env 中的 FLASK_PORT。")
        print("       若浏览器已能打开 http://localhost:{0}，请直接使用。".format(port))
        input("按回车键关闭窗口...")
        return 1

    print(f"访问地址: http://127.0.0.1:{port}（或 http://localhost:{port}）")
    print("服务启动中，浏览器将自动打开...")
    print("按 Ctrl+C 停止服务，关闭本窗口也会停止服务。")
    print()

    # 3) 延迟打开浏览器 + 启动服务
    #    双击场景使用单进程（关闭 debug 的自动重载），更稳定；
    #    需要调试模式请用 python -m app.main 启动。
    open_browser_later(port)
    from app.main import app
    app.run(host='0.0.0.0', port=port, debug=False)

    print()
    print("[服务已停止]")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print("[服务已停止]")
        input("按回车键关闭窗口...")
        sys.exit(0)
