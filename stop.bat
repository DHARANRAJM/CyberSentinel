@echo off
echo ========================================
echo    Stopping CyberSentinel Pro
echo ========================================
echo.

cd /d "%~dp0deploy"

echo Stopping all services...
docker-compose down

echo.
echo All services stopped successfully!
echo.
echo To start again, run: start.bat
echo To remove all data, run: docker-compose down -v
echo.
pause
