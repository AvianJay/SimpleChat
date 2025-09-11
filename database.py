import sqlite3
import string
import random
import hashlib

def init_database(db_name='app.db'):
    """Initialize the SQLite database with a sample table."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    # Create a sample table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            token TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,  -- can be user id or group id
            is_group BOOLEAN DEFAULT 0,  -- ⚠️ group -> is_group
            content TEXT NOT NULL UNIQUE,
            edited BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def create_connection(db_name='app.db'):
    """Create a database connection to the SQLite database."""
    conn = sqlite3.connect(db_name)
    return conn

def create_user(conn, name, email, password, token=None):
    """Create a new user in the users table."""
    if token is None:
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    password = hashlib.sha256(password.encode()).hexdigest()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (name, email, password, token)
        VALUES (?, ?, ?, ?)
    ''', (name, email, password, token))
    conn.commit()
    return cursor.lastrowid

def get_user(conn, user_id=None, email=None, token=None):
    """Retrieve a user from the users table."""
    cursor = conn.cursor()
    if user_id:
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    elif email:
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    elif token:
        cursor.execute('SELECT * FROM users WHERE token = ?', (token,))
    else:
        return None
    return cursor.fetchone()

def create_group(conn, name, description=None):
    """Create a new group in the groups table."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO groups (name, description)
        VALUES (?, ?)
    ''', (name, description))
    return cursor.lastrowid

def get_group(conn, group_id):
    """Retrieve a group from the groups table."""
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,))
    return cursor.fetchone()

def create_message(conn, author, chat_id, content, group=False):
    """Create a new message in the messages table."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (author, chat_id, content, is_group)  -- ⚠️ group -> is_group
        VALUES (?, ?, ?, ?)
    ''', (author, chat_id, content, int(group)))
    conn.commit()
    return cursor.lastrowid

def get_messages(conn, chat_id, group=False, limit=50):
    """Retrieve messages from the messages table."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM messages
        WHERE chat_id = ? AND is_group = ?  -- ⚠️ group → is_group
        ORDER BY created_at DESC
        LIMIT ?
    ''', (chat_id, int(group), limit))
    return cursor.fetchall()
