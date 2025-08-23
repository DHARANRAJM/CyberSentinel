import sqlite3 
import hashlib 
import uuid 
import json 
from datetime import datetime 
 
# Create SQLite database 
conn = sqlite3.connect('cybersentinel.db') 
cursor = conn.cursor() 
 
# Create users table 
cursor.execute('''CREATE TABLE IF NOT EXISTS users ( 
    id TEXT PRIMARY KEY, 
    email TEXT UNIQUE NOT NULL, 
    hashed_password TEXT NOT NULL, 
    role TEXT DEFAULT 'user', 
    is_active BOOLEAN DEFAULT 1, 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
)''') 
 
# Hash password function 
def hash_password(password): 
    return hashlib.sha256(password.encode()).hexdigest() 
 
# Create admin user 
admin_id = str(uuid.uuid4()) 
admin_email = 'admin@cybersentinel.local' 
admin_password = hash_password('admin123') 
 
cursor.execute('''INSERT OR REPLACE INTO users 
    (id, email, hashed_password, role, is_active) 
    VALUES (?, ?, ?, ?, ?)''', 
    (admin_id, admin_email, admin_password, 'admin', 1)) 
 
conn.commit() 
conn.close() 
 
print('Local database created successfully!') 
print('Admin user created:') 
print('Email: admin@cybersentinel.local') 
print('Password: admin123') 
