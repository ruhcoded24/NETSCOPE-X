@echo off
title NETSCOPE X Frontend (Vite)
echo =====================================================================
echo              NETSCOPE X - Frontend Dev Server
echo =====================================================================
echo.

cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo [*] Installing frontend dependencies...
    npm install
)

echo [*] Starting Vite frontend on http://localhost:3000...
npm run dev
pause
