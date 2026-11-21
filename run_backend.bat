@echo off
setlocal enabledelayedexpansion

title NETSCOPE X - Real-time Network Monitoring & Forensics Backend
echo =====================================================================
echo              NETSCOPE X - Real-time Backend Engine
echo =====================================================================
echo.

:: 1. Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found in PATH.
    echo Please install Python 3.10+ from https://www.python.org/ and check "Add Python to PATH".
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version') do set PYTHON_VER=%%v
echo [OK] Detected Python: !PYTHON_VER!

:: 2. Check Wireshark / TShark
set TSHARK_EXE=C:\Program Files\Wireshark\tshark.exe
if not exist "!TSHARK_EXE!" (
    echo [WARNING] TShark was not found at standard path "!TSHARK_EXE!".
    echo Live capture will require Wireshark with Npcap installed.
    echo You can configure a custom TSHARK_PATH in backend\.env if installed elsewhere.
) else (
    echo [OK] Detected TShark: !TSHARK_EXE!
)

:: 3. Change directory to backend
cd /d "%~dp0backend"
if not exist "requirements.txt" (
    echo [ERROR] Could not find backend\requirements.txt.
    pause
    exit /b 1
)

:: 4. Ensure dependencies are satisfied
echo.
echo [*] Verifying backend dependencies...
python -m pip install -r requirements.txt --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Some dependencies could not be auto-installed. Attempting launch...
)

:: 5. Copy .env if not exists
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo [OK] Created default backend\.env configuration.
    )
)

:: 6. Launch Uvicorn
echo.
echo =====================================================================
echo  NETSCOPE X Backend is starting on http://127.0.0.1:8000
echo  - API Documentation: http://127.0.0.1:8000/docs
echo  - WebSocket Stream:   ws://127.0.0.1:8000/ws
echo =====================================================================
echo.
echo Press Ctrl+C in this terminal to stop the backend.
echo.

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

pause
