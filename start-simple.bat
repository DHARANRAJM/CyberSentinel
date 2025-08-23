@echo off
echo ========================================
echo    CyberSentinel Pro - Simple Start
echo ========================================
echo.

echo [1/3] Setting up local database...
cd /d "%~dp0"
call setup-local-admin.bat

echo.
echo [2/3] Starting backend API...
cd /d "%~dp0api"
start "CyberSentinel API" cmd /k "echo Starting API Server... && python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

echo.
echo [3/3] Starting frontend...
cd /d "%~dp0web"
start "CyberSentinel Web" cmd /k "echo Starting Web Server... && npm run dev"

echo.
echo ========================================
echo    CyberSentinel Pro Started!
echo ========================================
echo.
echo Web Dashboard: http://localhost:3000
echo API Backend:   http://localhost:8000
echo API Docs:      http://localhost:8000/docs
echo.
echo Login with:
echo Email: admin@cybersentinel.local
echo Password: admin123
echo.
echo Press any key to continue...
pause
