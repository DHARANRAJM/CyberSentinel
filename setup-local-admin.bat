@echo off
echo ========================================
echo    CyberSentinel Pro - Local Admin Setup
echo ========================================
echo.

echo Setting up local database and admin user...
echo Note: This creates a local SQLite database for development

cd /d "%~dp0api"

echo Creating admin setup script...
echo import sqlite3 > setup_admin.py
echo import hashlib >> setup_admin.py
echo import uuid >> setup_admin.py
echo import json >> setup_admin.py
echo from datetime import datetime >> setup_admin.py
echo. >> setup_admin.py
echo # Create SQLite database >> setup_admin.py
echo conn = sqlite3.connect('cybersentinel.db') >> setup_admin.py
echo cursor = conn.cursor() >> setup_admin.py
echo. >> setup_admin.py
echo # Create users table >> setup_admin.py
echo cursor.execute('''CREATE TABLE IF NOT EXISTS users ( >> setup_admin.py
echo     id TEXT PRIMARY KEY, >> setup_admin.py
echo     email TEXT UNIQUE NOT NULL, >> setup_admin.py
echo     hashed_password TEXT NOT NULL, >> setup_admin.py
echo     role TEXT DEFAULT 'user', >> setup_admin.py
echo     is_active BOOLEAN DEFAULT 1, >> setup_admin.py
echo     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP >> setup_admin.py
echo )''') >> setup_admin.py
echo. >> setup_admin.py
echo # Hash password function >> setup_admin.py
echo def hash_password(password): >> setup_admin.py
echo     return hashlib.sha256(password.encode()).hexdigest() >> setup_admin.py
echo. >> setup_admin.py
echo # Create admin user >> setup_admin.py
echo admin_id = str(uuid.uuid4()) >> setup_admin.py
echo admin_email = 'admin@cybersentinel.local' >> setup_admin.py
echo admin_password = hash_password('admin123') >> setup_admin.py
echo. >> setup_admin.py
echo cursor.execute('''INSERT OR REPLACE INTO users >> setup_admin.py
echo     (id, email, hashed_password, role, is_active) >> setup_admin.py
echo     VALUES (?, ?, ?, ?, ?)''', >> setup_admin.py
echo     (admin_id, admin_email, admin_password, 'admin', 1)) >> setup_admin.py
echo. >> setup_admin.py
echo conn.commit() >> setup_admin.py
echo conn.close() >> setup_admin.py
echo. >> setup_admin.py
echo print('Local database created successfully!') >> setup_admin.py
echo print('Admin user created:') >> setup_admin.py
echo print('Email: admin@cybersentinel.local') >> setup_admin.py
echo print('Password: admin123') >> setup_admin.py

echo Running admin setup...
python setup_admin.py

echo.
echo ========================================
echo    Local Setup Complete!
echo ========================================
echo.
echo Database: cybersentinel.db (SQLite)
echo Admin Email: admin@cybersentinel.local
echo Admin Password: admin123
echo.
echo You can now start the servers:
echo 1. Backend: python -m uvicorn app.main:app --reload
echo 2. Frontend: cd ../web && npm run dev
echo.
pause
