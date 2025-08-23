@echo off
echo ========================================
echo    CyberSentinel Pro - Local Execution
echo ========================================
echo.

echo Checking system requirements...

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed!
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed!
    echo Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

echo Python and Node.js found!
echo.

echo ========================================
echo    Starting CyberSentinel Pro Locally
echo ========================================
echo.

echo [1/4] Installing Python dependencies...
cd /d "%~dp0api"
pip install fastapi uvicorn sqlalchemy psycopg2-binary redis celery python-jose[cryptography] passlib[bcrypt] python-multipart

echo.
echo [2/4] Installing Node.js dependencies...
cd /d "%~dp0web"
npm install

echo.
echo [3/4] Starting backend server...
cd /d "%~dp0api"
start "CyberSentinel API" cmd /k "uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

echo.
echo [4/4] Starting frontend server...
cd /d "%~dp0web"
start "CyberSentinel Web" cmd /k "npm run dev"

echo.
echo ========================================
echo    CyberSentinel Pro Started!
echo ========================================
echo.
echo Backend API: http://localhost:8000
echo Frontend:    http://localhost:3000
echo API Docs:    http://localhost:8000/docs
echo.
echo Note: This runs without Docker and database.
echo For full functionality, install Docker and use Docker Compose.
echo.
pause
