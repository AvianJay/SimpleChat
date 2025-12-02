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
        CREATE TABLE IF NOT EXISTS user_dms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            dm_id INTEGER NOT NULL,
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
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member',  -- member, admin owner
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, user_id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,  -- can be user_dms id or group id
            is_group BOOLEAN DEFAULT 0,
            content TEXT NOT NULL,
            edited BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',  -- pending, accepted, blocked
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, friend_id)
        )
    ''')

    conn.commit()
    conn.close()

def create_connection(db_name='app.db'):
    """Create a database connection to the SQLite database."""
    conn = sqlite3.connect(db_name, check_same_thread=False)
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

def get_user(conn, user_id=None, user_name=None, email=None, token=None):
    """Retrieve a user from the users table."""
    cursor = conn.cursor()
    if user_id:
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    elif user_name:
        cursor.execute('SELECT * FROM users WHERE name = ?', (user_name,))
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

def get_group(conn, group_id=None, user_id=None):
    """Retrieve a group from the groups table."""
    cursor = conn.cursor()
    if group_id:
        cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,))
    elif user_id:
        cursor.execute('SELECT * FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?', (user_id,))
    return cursor.fetchone()

def create_message(conn, author, chat_id, content, group=False):
    """Create a new message in the messages table and return its id."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (author, chat_id, content, is_group)
        VALUES (?, ?, ?, ?)
    ''', (author, chat_id, content, int(group)))
    conn.commit()
    return cursor.lastrowid

def get_messages(conn, chat_id, group=False, limit=50):
    """Retrieve messages from the messages table."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM messages
        WHERE chat_id = ? AND is_group = ?
        ORDER BY created_at DESC
        LIMIT ?
    ''', (chat_id, int(group), limit))
    messages = cursor.fetchall()
    # convert messages to list of dictionaries
    messages = [{
        'id': message[0],
        'author': message[1],
        'chat_id': message[2],
        'is_group': message[3],
        'content': message[4],
        'edited': message[5],
        'created_at': message[6]
    } for message in messages]
    return messages

def friend(conn, user_id, friend_id, status='pending'):
    """Create a friendship or update its status."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO friendships (user_id, friend_id, status)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, friend_id) DO UPDATE SET status=excluded.status
    ''', (user_id, friend_id, status))
    if status == 'accepted':
        cursor.execute('''
            INSERT INTO friendships (user_id, friend_id, status)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, friend_id) DO UPDATE SET status=excluded.status
        ''', (friend_id, user_id, status))
    conn.commit()
    if status == 'accepted':
        create_user_dm(conn, user_id, friend_id)
    return cursor.lastrowid

def friend_status(conn, user_id, friend_id):
    """Get the status of a friendship."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT status FROM friendships
        WHERE user_id = ? AND friend_id = ?
    ''', (user_id, friend_id))
    row = cursor.fetchone()
    if row:
        return row[0]
    return None

def get_friends(conn, user_id):
    """Retrieve a list of friends for a user."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.name, u.email, f.status
        FROM users u
        JOIN friendships f ON u.id = f.friend_id
        WHERE f.user_id = ? AND f.status = 'accepted'
    ''', (user_id,))
    return cursor.fetchall()

def get_pending_requests(conn, user_id):
    """Retrieve a list of pending friend requests for a user."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.name, u.email
        FROM users u
        JOIN friendships f ON u.id = f.user_id
        WHERE f.friend_id = ? AND f.status = 'pending'
    ''', (user_id,))
    return cursor.fetchall()

def get_chats(conn, user_id):
    """Retrieve a list of chats (both user and group) for a user."""
    cursor = conn.cursor()
    # User chats
    cursor.execute('''
        SELECT
            CASE
                WHEN udm.user_id = ? THEN udm.target_id
                ELSE udm.user_id
            END AS friend_id,
            u.name,
            u.email,
            udm.dm_id,
            'user' AS chat_type
        FROM user_dms udm
        JOIN users u ON u.id = CASE
                                    WHEN udm.user_id = ? THEN udm.target_id
                                    ELSE udm.user_id
                                END
        JOIN friendships f ON (f.user_id = ? AND f.friend_id = u.id)
        WHERE udm.user_id = ? AND f.status = 'accepted'
    ''', (user_id, user_id, user_id, user_id))
    user_chats = cursor.fetchall()
    user_chats = [{
        'id': chat[3],
        'name': chat[1],
        'email': chat[2],
        'user_id': chat[0],
        'chat_type': 'user'
    } for chat in user_chats]
    
    # Group chats
    cursor.execute('''
        SELECT g.id, g.name, g.description, 'group' AS chat_type
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = ?
    ''', (user_id,))
    group_chats = cursor.fetchall()
    # convert group chats to list of dictionaries
    group_chats = [{
        'id': chat[0],
        'name': chat[1],
        'description': chat[2],
        'chat_type': 'group'
    } for chat in group_chats]

    return user_chats + group_chats

def add_group_member(conn, group_id, user_id, role='member'):
    """Add a user to a group."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO group_members (group_id, user_id, role)
        VALUES (?, ?, ?)
    ''', (group_id, user_id, role))
    conn.commit()

def remove_group_member(conn, group_id, user_id):
    """Remove a user from a group."""
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM group_members
        WHERE group_id = ? AND user_id = ?
    ''', (group_id, user_id))
    conn.commit()

def get_group_members(conn, group_id):
    """Get all members of a group."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.name, u.email, gm.role
        FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
    ''', (group_id,))
    # convert group members to list of dictionaries
    group_members = cursor.fetchall()
    group_members = [{
        'id': member[0],
        'name': member[1],
        'email': member[2],
        'role': member[3]
    } for member in group_members]
    return group_members

def delete_friend(conn, user_id, friend_id):
    """Delete a friendship."""
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM friendships
        WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    ''', (user_id, friend_id, friend_id, user_id))
    conn.commit()

def update_message(conn, message_id, content):
    """Update a message content."""
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE messages
        SET content = ?, edited = 1
        WHERE id = ?
    ''', (content, message_id))
    conn.commit()

def delete_message(conn, message_id):
    """Delete a message."""
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM messages
        WHERE id = ?
    ''', (message_id,))
    conn.commit()

def get_message(conn, message_id):
    """Get a message by ID."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM messages WHERE id = ?
    ''', (message_id,))
    message = cursor.fetchone()
    # convert message to dictionary
    message = {
        'id': message[0],
        'author': message[1],
        'chat_id': message[2],
        'is_group': message[3],
        'content': message[4],
        'edited': message[5],
        'created_at': message[6]
    }
    return message

def delete_group(conn, group_id):
    """Delete a group and all its members and messages."""
    cursor = conn.cursor()
    # Delete group
    cursor.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    # Delete members
    cursor.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
    # Delete messages
    cursor.execute('DELETE FROM messages WHERE chat_id = ? AND is_group = 1', (group_id,))
    conn.commit()

def get_user_dm(conn, user_id=None, target_id=None, dm_id=None):
    """Get a user DM."""
    cursor = conn.cursor()
    if dm_id:
        if user_id:
            cursor.execute('''
                SELECT * FROM user_dms WHERE dm_id = ? AND user_id = ?
            ''', (dm_id, user_id))
        else:
            cursor.execute('''
                SELECT * FROM user_dms WHERE dm_id = ?
            ''', (dm_id,))
    else:
        cursor.execute('''
            SELECT * FROM user_dms WHERE user_id = ? AND target_id = ?
        ''', (user_id, target_id))
    user_dm = cursor.fetchone()
    # convert user_dm to dictionary
    user_dm = {
        'id': user_dm[3],
        'user_id': user_dm[1],
        'target_id': user_dm[2],
        'created_at': user_dm[4]
    }
    return user_dm

def get_user_dms(conn, user_id):
    """Get all DMs of a user."""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM user_dms WHERE user_id = ?
    ''', (user_id,))
    # convert user_dms to list of dictionaries
    user_dms = cursor.fetchall()
    user_dms = [{
        'id': user_dm[3],
        'user_id': user_dm[1],
        'target_id': user_dm[2],
        'created_at': user_dm[4]
    } for user_dm in user_dms]
    return user_dms

def create_user_dm(conn, user_id, target_id):
    """Create a new user DM."""
    # check there is no existing DM between user and target
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM user_dms WHERE user_id = ? AND target_id = ?
    ''', (user_id, target_id))
    if cursor.fetchone():
        return
    while True:
        dm_id = random.randint(1, 1000000)
        cursor.execute('''
            SELECT * FROM user_dms WHERE id = ?
        ''', (dm_id,))
        if not cursor.fetchone():
            break
    cursor.execute('''
        INSERT INTO user_dms (user_id, target_id, dm_id)
        VALUES (?, ?, ?)
    ''', (user_id, target_id, dm_id))
    cursor.execute('''
        INSERT INTO user_dms (user_id, target_id, dm_id)
        VALUES (?, ?, ?)
    ''', (target_id, user_id, dm_id))
    conn.commit()
