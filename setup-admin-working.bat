@echo off
echo ========================================
echo    CyberSentinel Pro - Working Admin Setup
echo ========================================
echo.

cd /d "%~dp0deploy"

echo Checking container status...
docker-compose ps

echo.
echo Waiting for API container to be ready...
timeout /t 15 /nobreak >nul

echo.
echo Creating admin user with direct database approach...
docker-compose exec -T db psql -U cybersentinel -d cybersentinel -c "
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (id, email, hashed_password, role, is_active) 
VALUES (
    'admin-' || EXTRACT(EPOCH FROM NOW())::text,
    'admin@cybersentinel.local',
    '\$2b\$12\$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
    'admin',
    true
) ON CONFLICT (email) DO NOTHING;

SELECT 'Admin user setup complete!' as status;
"

echo.
echo ========================================
echo    Admin Setup Complete!
echo ========================================
echo.
echo You can now access CyberSentinel Pro:
echo Web Dashboard: http://localhost:3000
echo API Backend:   http://localhost:8000
echo API Docs:      http://localhost:8000/docs
echo.
echo Login credentials:
echo Email: admin@cybersentinel.local
echo Password: admin123
echo.
echo Note: Password is hashed with bcrypt
echo.
pause
