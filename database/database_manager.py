import sqlite3
import bcrypt
from datetime import datetime
import os

# Get the absolute path to the database
DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "scan_history.db")


# ---------------- CONNECTION ----------------
def get_connection():
    return sqlite3.connect(DB_PATH)


# ---------------- TABLE CREATION ----------------
def create_tables():
    conn = get_connection()
    c = conn.cursor()

    # 🔐 USERS TABLE (NEW)
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT UNIQUE NOT NULL,
        password BLOB NOT NULL,
        created_at TEXT
    )
    """)

    # Ensure the users table has all required columns (schema migrations)
    c.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in c.fetchall()}

    if 'username' not in existing_columns:
        c.execute("ALTER TABLE users ADD COLUMN username TEXT")
    if 'created_at' not in existing_columns:
        c.execute("ALTER TABLE users ADD COLUMN created_at TEXT")

    # 📊 SCAN HISTORY TABLE (EXISTING)
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        scan_type TEXT,
        result TEXT,
        confidence REAL,
        timestamp TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


# ---------------- PASSWORD SECURITY ----------------
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


# ---------------- USER FUNCTIONS ----------------

# SIGN UP
def register_user(username, email, password):
    conn = get_connection()
    c = conn.cursor()

    hashed_pw = hash_password(password)

    try:
        c.execute("""
        INSERT INTO users (username, email, password, created_at)
        VALUES (?, ?, ?, ?)
        """, (username, email, hashed_pw, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# LOGIN
def login_user(email, password):
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    user = c.fetchone()

    conn.close()

    if user:
        stored_password = user[3]
        if verify_password(password, stored_password):
            return user  # return full user data

    return None


# RESET PASSWORD
def reset_password(email, new_password):
    conn = get_connection()
    c = conn.cursor()
    try:
        clean_email = email.strip().lower()
        c.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (clean_email,))
        user = c.fetchone()
        if not user:
            return False, "No account found with this email address."

        hashed_pw = hash_password(new_password)
        c.execute("UPDATE users SET password = ? WHERE LOWER(email) = LOWER(?)", (hashed_pw, clean_email))
        conn.commit()
        return True, "Password reset successfully!"
    except Exception as e:
        return False, f"Database error: {str(e)}"
    finally:
        conn.close()


def check_user_email(email):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, email FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    user = c.fetchone()
    conn.close()
    return user is not None


# ---------------- SCAN HISTORY FUNCTIONS ----------------

def get_user_by_id(user_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return user

def save_scan(user_id, scan_type, result, confidence):
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    INSERT INTO scan_history (user_id, scan_type, result, confidence, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        scan_type,
        result,
        confidence,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_user_history(user_id):
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    SELECT scan_type, result, confidence, timestamp
    FROM scan_history
    WHERE user_id = ?
    ORDER BY timestamp DESC
    """, (user_id,))

    data = c.fetchall()
    conn.close()

    return data