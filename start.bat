@echo off
echo ========================================
echo    CyberSentinel Pro - Quick Start
echo ========================================
echo.

REM Check if Docker is running
docker version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not running or not installed!
    echo Please install Docker Desktop and make sure it's running.
    pause
    exit /b 1
)

echo [1/4] Setting up environment...
cd /d "%~dp0deploy"

REM Copy environment file if it doesn't exist
if not exist .env (
    echo Copying environment template...
    copy .env.example .env
    echo.
    echo IMPORTANT: Please edit deploy\.env file with your settings!
    echo At minimum, change the passwords and secret keys.
    echo.
    pause
)

echo [2/4] Starting services with Docker Compose...
docker-compose up -d

echo.
echo [3/4] Waiting for services to start...
timeout /t 10 /nobreak >nul

echo [4/4] Checking service status...
docker-compose ps

echo.
echo ========================================
echo    CyberSentinel Pro is starting up!
echo ========================================
echo.
echo Web Dashboard: http://localhost:3000
echo API Backend:   http://localhost:8000
echo API Docs:      http://localhost:8000/docs
echo MinIO Console: http://localhost:9001
echo.
echo To create admin user, run: setup-admin.bat
echo To stop services, run: stop.bat
echo.
echo Services are starting in the background...
echo Check status with: docker-compose ps
echo View logs with: docker-compose logs -f
echo.
pause
