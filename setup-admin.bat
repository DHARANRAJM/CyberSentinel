@echo off
echo ========================================
echo    Creating CyberSentinel Pro Admin User
echo ========================================
echo.

cd /d "%~dp0deploy"

echo Initializing database tables...
docker-compose exec -T api python -c "
from app.database import engine
from app.models import Base
Base.metadata.create_all(bind=engine)
print('Database initialized successfully')
"

echo.
echo Creating admin user...
docker-compose exec -T api python -c "
from app.database import SessionLocal
from app.models import User
from app.auth import get_password_hash
import uuid

db = SessionLocal()
try:
    # Check if admin already exists
    existing_admin = db.query(User).filter(User.email == 'admin@cybersentinel.local').first()
    if existing_admin:
        print('Admin user already exists!')
    else:
        admin_user = User(
            id=str(uuid.uuid4()),
            email='admin@cybersentinel.local',
            hashed_password=get_password_hash('admin123'),
            role='admin',
            is_active=True
        )
        db.add(admin_user)
        db.commit()
        print('Admin user created successfully!')
        print('Email: admin@cybersentinel.local')
        print('Password: admin123')
        print('')
        print('IMPORTANT: Change this password after first login!')
except Exception as e:
    print(f'Error creating admin user: {e}')
finally:
    db.close()
"

echo.
echo ========================================
echo    Admin Setup Complete!
echo ========================================
echo.
echo You can now login to the web dashboard at:
echo http://localhost:3000
echo.
echo Default admin credentials:
echo Email: admin@cybersentinel.local
echo Password: admin123
echo.
echo SECURITY: Please change the password after first login!
echo.
pause
