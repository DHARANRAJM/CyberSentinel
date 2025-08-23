@echo off
echo ========================================
echo    CyberSentinel Pro - Emergency Fix
echo ========================================
echo.

echo [1/4] Stopping all containers...
cd /d "%~dp0deploy"
docker-compose down

echo.
echo [2/4] Removing problematic API image...
docker rmi deploy-api 2>nul

echo.
echo [3/4] Starting database and frontend only...
docker-compose up -d db redis web minio

echo.
echo [4/4] Creating direct database admin user...
timeout /t 5 /nobreak >nul

docker-compose exec -T db psql -U cybersentinel -d cybersentinel -c "CREATE TABLE IF NOT EXISTS users (id VARCHAR(36) PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, hashed_password VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'user', is_active BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"

docker-compose exec -T db psql -U cybersentinel -d cybersentinel -c "INSERT INTO users (id, email, hashed_password, role, is_active) VALUES ('admin-001', 'admin@cybersentinel.local', '\$2b\$12\$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'admin', true) ON CONFLICT (email) DO NOTHING;"

echo.
echo [5/5] Starting API with local Python...
cd /d "%~dp0api"
echo Starting API server locally...
start "CyberSentinel API" cmd /k "python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

echo.
echo ========================================
echo    Emergency Fix Complete!
echo ========================================
echo.
echo Web Dashboard: http://localhost:3000
echo API Backend:   http://localhost:8000 (Local Python)
echo.
echo Login: admin@cybersentinel.local / admin123
echo.
pause
