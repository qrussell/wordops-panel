import os
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext

# --- CONFIGURATION ---
DB_PATH = "/var/lib/wo/wordops-panel_users.db"
KEY_FILE = "/var/lib/wo/secret.key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# --- PERSISTENT SECRET KEY ---
def get_secret_key():
    # Ensure directory exists
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            return f.read().strip()
    else:
        # Generate new key and save it
        key = os.urandom(32).hex()
        with open(KEY_FILE, "w") as f:
            f.write(key)
        # Set restricted permissions
        os.chmod(KEY_FILE, 0o600)
        return key

SECRET_KEY = get_secret_key()

# --- SECURITY SETUP ---
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except:
        return False

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- DATABASE MANAGEMENT ---
def init_user_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)''')
    
    # Create default admin if table is empty
    c.execute("SELECT count(*) FROM users")
    if c.fetchone()[0] == 0:
        print("Creating default admin user...")
        # Default: admin / wordops
        admin_pass = get_password_hash("wordops")
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", admin_pass))
        print("Default user 'admin' created with password 'wordops'")
    
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        hashed = get_password_hash(password)
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def delete_user(username):
    # Prevent deleting the last user or 'admin' if you prefer
    if username == "admin": return False 
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return True

def list_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return users