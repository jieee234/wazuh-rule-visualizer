@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Please install Python 3.8+ and check "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

python scripts\launcher.py
if errorlevel 1 (
    echo.
    echo [ERROR] Startup failed, see messages above.
    echo.
    pause
)
endlocal
