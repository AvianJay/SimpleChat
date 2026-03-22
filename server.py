from flask import Flask, request, render_template, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask import session
import database
from graph_mailer import GraphMailer
import hashlib
import os
import re
import time
import uuid
import secrets
from config import config
import notifications
import threading
import asyncio
from collections import defaultdict, deque
from functools import wraps
from werkzeug.utils import secure_filename
from hypercorn.asyncio import serve
from hypercorn.config import Config
from hypercorn.middleware import AsyncioWSGIMiddleware
import socketio as sio_lib

database.init_database(config("database_path"))
conn = database.create_connection(config("database_path"))
USERNAME_PATTERN = re.compile(r'^[a-z0-9._-]{3,20}$')
RATE_LIMIT_STORAGE = defaultdict(deque)
RATE_LIMIT_LOCK = threading.Lock()
AVATAR_UPLOAD_DIR = os.path.join('static', 'uploads', 'avatars')
ALLOWED_AVATAR_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.gif'}
MAX_AVATAR_SIZE = 2 * 1024 * 1024

app = Flask(__name__)
# secret key required for flask session and socketio session management
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = MAX_AVATAR_SIZE
# manage_session=True lets Flask-SocketIO use Flask's session inside events
socketio = SocketIO(app, manage_session=True)

# Initialize VAPID keys for push notifications
VAPID_PUBLIC_KEY = notifications.init_vapid_keys()

def verify_user(token, admin_required=False):
    user = database.get_user(conn, token=token)
    if user is None:
        return False
    if admin_required:
        # user row: id, name, email, password, role, token, created_at
        return user[4] == 'admin'
    return True


def normalize_username(value):
    return (value or '').strip().lower()


def normalize_display_name(value, fallback):
    display_name = (value or '').strip()
    return display_name[:50] if display_name else fallback


def get_user_display_name(user):
    return user[7] if len(user) > 7 and user[7] else user[1]


def get_user_avatar_path(user):
    return user[8] if len(user) > 8 and user[8] else None


def build_avatar_url(avatar_path):
    if not avatar_path:
        return None
    normalized = avatar_path.replace('\\', '/').lstrip('/')
    return f"/{normalized}"


def build_user_payload(user):
    return {
        'id': user[0],
        'username': user[1],
        'display_name': get_user_display_name(user),
        'avatar_path': get_user_avatar_path(user),
        'avatar_url': build_avatar_url(get_user_avatar_path(user)),
        'email_verified': bool(user[9]) if len(user) > 9 else False,
        'email': user[2],
        'role': user[4],
        'created_at': user[6]
    }


def get_group_member_ids(group_id):
    return [member['id'] for member in database.get_group_members(conn, group_id)]


def users_share_group(user_id, other_user_id):
    return database.users_share_group(conn, user_id, other_user_id)


def can_view_user(viewer_id, target_id):
    if viewer_id == target_id:
        return True
    if database.friend_status(conn, viewer_id, target_id) == 'accepted':
        return True
    return users_share_group(viewer_id, target_id)


def get_rate_limit_key(scope='ip'):
    if scope == 'token':
        token = None
        if request.method == 'POST':
            payload = request.get_json(silent=True) or {}
            token = payload.get('token') or request.form.get('token')
        else:
            token = request.args.get('token')
        if token:
            return f"token:{token}"
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr
    return f"ip:{client_ip or 'unknown'}"


def rate_limit(max_requests, window_seconds, scope='ip'):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            key = f"{func.__name__}:{get_rate_limit_key(scope)}"
            with RATE_LIMIT_LOCK:
                attempts = RATE_LIMIT_STORAGE[key]
                while attempts and now - attempts[0] >= window_seconds:
                    attempts.popleft()
                if len(attempts) >= max_requests:
                    retry_after = max(1, int(window_seconds - (now - attempts[0])))
                    response = jsonify({
                        'error': 'Too many requests',
                        'retry_after': retry_after
                    })
                    response.status_code = 429
                    response.headers['Retry-After'] = str(retry_after)
                    return response
                attempts.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

def background_send_message_notification(db_path, recipient_id, sender_name, content, chat_name):
    """
    Background task to send message notifications.
    Creates a new database connection to be thread-safe.
    """
    # Create a new connection for this thread
    thread_conn = database.create_connection(db_path)
    try:
        notifications.send_message_notification(
            thread_conn, recipient_id, sender_name, content, chat_name
        )
    except Exception as e:
        print(f"Error sending notification in background: {e}")
    finally:
        thread_conn.close()

def get_request_data(request):
    if request.method == 'POST':
        reqdata = request.get_json() or request.form.copy()
    else:
        reqdata = request.args.copy()
    return reqdata


def validate_avatar_upload(file_storage):
    if file_storage is None or not file_storage.filename:
        return 'Avatar file is required'
    filename = secure_filename(file_storage.filename)
    extension = os.path.splitext(filename)[1].lower()
    if extension not in ALLOWED_AVATAR_EXTENSIONS:
        return 'Unsupported avatar format'
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size <= 0:
        return 'Avatar file is empty'
    if size > MAX_AVATAR_SIZE:
        return 'Avatar must be 2MB or smaller'
    if not (file_storage.mimetype or '').startswith('image/'):
        return 'Unsupported avatar format'
    return None


def get_graph_mailer():
    if not config('mail_enabled'):
        return None
    required_keys = ['mail_tenant_id', 'mail_client_id', 'mail_client_secret', 'mail_sender']
    if not all(config(key) for key in required_keys):
        return None
    return GraphMailer(
        tenant_id=config('mail_tenant_id'),
        client_id=config('mail_client_id'),
        client_secret=config('mail_client_secret'),
        verify_ssl=config('mail_verify_ssl')
    )


def send_verification_email(user, verification_token):
    mailer = get_graph_mailer()
    if mailer is None:
        return False, 'Mail service is not configured'

    verification_url = f"{config('public_base_url').rstrip('/')}/verify_email?token={verification_token}"
    message_args = {
        'subject': 'Verify your SimpleChat email',
        'toRecipients': [{'address': user[2], 'name': get_user_display_name(user)}],
        'body': (
            f"<p>Hello {get_user_display_name(user)},</p>"
            f"<p>Please verify your email for SimpleChat by clicking the link below:</p>"
            f"<p><a href=\"{verification_url}\">{verification_url}</a></p>"
            "<p>If you did not create this account, you can ignore this email.</p>"
        )
    }
    result = mailer.send_mail(config('mail_sender'), message_args)
    return (bool(result), None if result else 'Failed to send verification email')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
@rate_limit(5, 300, scope='ip')
def api_register():
    data = get_request_data(request)
    if not data or 'username' not in data or 'email' not in data or 'password' not in data:
        return {'error': 'Invalid input'}, 400
    if get_graph_mailer() is None:
        return {'error': 'Email verification is not configured'}, 503
    username = normalize_username(data['username'])
    if not USERNAME_PATTERN.fullmatch(username):
        return {'error': 'Username must be 3-20 characters and only use lowercase letters, numbers, ., _, -'}, 400
    if len(data['password']) < 8:
        return {'error': 'Password must be at least 8 characters'}, 400
    if database.get_user(conn, email=data['email']) is not None:
        return {'error': 'Email already registered'}, 400
    if database.get_user(conn, user_name=username) is not None:
        return {'error': 'Username already taken'}, 400
    display_name = normalize_display_name(data.get('display_name'), username)
    user_id = database.create_user_with_profile(conn, username, data['email'], data['password'], display_name=display_name)
    verification_token = secrets.token_urlsafe(32)
    database.set_email_verification_token(conn, user_id, verification_token)
    user = database.get_user(conn, user_id=user_id)
    sent, error = send_verification_email(user, verification_token)
    return {
        'message': 'User registered. Please verify your email before logging in.',
        'user_id': user_id,
        'verification_email_sent': sent,
        'mail_error': error
    }, 201

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
@rate_limit(10, 60, scope='ip')
def api_login():
    data = get_request_data(request)
    if not data or 'username' not in data or 'password' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, user_name=normalize_username(data['username']))
    if user is None:
        return {'error': 'User not found'}, 404
    if len(user) > 9 and not user[9]:
        return {'error': 'Email not verified'}, 403
    hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
    if user[3] != hashed_password:
        return {'error': 'Incorrect password'}, 401
    return {'message': 'Login successful', 'token': user[5]}, 200

@app.route('/verify_email', methods=['GET'])
def verify_email():
    verification_token = request.args.get('token')
    if not verification_token:
        return {'error': 'Missing verification token'}, 400
    user = database.get_user_by_email_verification_token(conn, verification_token)
    if user is None:
        return render_template('home.html'), 400
    database.verify_user_email(conn, verification_token)
    return render_template('login.html')

@app.route('/api/verify_email/resend', methods=['POST'])
@rate_limit(5, 300, scope='ip')
def api_resend_verification_email():
    data = get_request_data(request)
    if not data or ('email' not in data and 'username' not in data):
        return {'error': 'Invalid input'}, 400
    user = None
    if data.get('email'):
        user = database.get_user(conn, email=data['email'])
    elif data.get('username'):
        user = database.get_user(conn, user_name=normalize_username(data['username']))
    if user is None:
        return {'error': 'User not found'}, 404
    if len(user) > 9 and user[9]:
        return {'message': 'Email already verified'}, 200

    verification_token = secrets.token_urlsafe(32)
    database.set_email_verification_token(conn, user[0], verification_token)
    sent, error = send_verification_email(database.get_user(conn, user_id=user[0]), verification_token)
    if not sent:
        return {'error': error or 'Failed to send verification email'}, 500
    return {'message': 'Verification email sent'}, 200

@app.route('/api/reset_password', methods=['POST'])
@rate_limit(5, 300, scope='token')
def api_reset_password():
    data = get_request_data(request)
    if not data or 'token' not in data or 'old_password' not in data or 'new_password' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    hashed_old_password = hashlib.sha256(data['old_password'].encode()).hexdigest()
    if user[3] != hashed_old_password:
        return {'error': 'Incorrect old password'}, 401
    new_hashed_password = hashlib.sha256(data['new_password'].encode()).hexdigest()
    cursor = conn.cursor()
    # update by user id obtained from the token
    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed_password, user[0]))
    conn.commit()
    return {'message': 'Password reset successful'}, 200

@app.route('/api/friend_request', methods=['POST'])
@rate_limit(10, 300, scope='token')
def api_friend_request():
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    friend_id = None
    # check if friend_id exists
    try:
        if data.get('friend_id') not in (None, ''):
            friend_id = int(data['friend_id'])
        elif data.get('friend_username'):
            friend_user = database.get_user(conn, user_name=normalize_username(data['friend_username']))
            if friend_user is None:
                return {'error': 'Friend not found'}, 404
            friend_id = friend_user[0]
        else:
            return {'error': 'friend_id or friend_username is required'}, 400
    except (ValueError, TypeError):
        return {'error': 'Invalid friend_id'}, 400
    if friend_id == user[0]:
        return {'error': 'Cannot friend yourself'}, 400
    friend_user = database.get_user(conn, user_id=friend_id)
    if friend_user is None:
        return {'error': 'Friend not found'}, 404
    # check existing friendship status from both directions
    friend_status = database.friend_status(conn, user[0], friend_id)
    reverse_status = database.friend_status(conn, friend_id, user[0])
    if friend_status == 'accepted':
        return {'error': 'Already friends'}, 400
    elif friend_status == 'pending':
        return {'error': 'Friend request already sent'}, 400
    elif friend_status == 'blocked':
        return {'error': 'You have blocked this user'}, 400
    elif reverse_status == 'blocked':
        return {'error': 'You are blocked by this user'}, 400
    else:
        # check if target user is already sent a friend request
        if reverse_status == 'pending':
            # update the status to accepted
            database.friend(conn, user[0], friend_id, status='accepted')
            emit('update_chat_list', namespace='/chat', to=str(user[0]))
            emit('update_chat_list', namespace='/chat', to=str(friend_id))
            emit('friend_request_accepted', {'user_id': user[0], 'name': get_user_display_name(user)}, namespace='/chat', to=str(friend_id))
            # Send push notification to the friend
            notifications.send_friend_accepted_notification(conn, friend_id, get_user_display_name(user))
            return {'message': 'Friend request accepted'}, 200
        else:
            database.friend(conn, user[0], friend_id, status='pending')
            emit('got_friend_request', {'user_id': user[0], 'name': get_user_display_name(user)}, namespace='/chat', to=str(friend_id))
            # Send push notification to the friend
            notifications.send_friend_request_notification(conn, friend_id, get_user_display_name(user))
            return {'message': 'Friend request sent'}, 200

@app.route('/api/friends', methods=['POST'])
def api_get_friends():
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    friends = database.get_friends(conn, user[0])
    friends_list = [{
        'id': f[0],
        'username': f[1],
        'display_name': f[4] or f[1],
        'email': f[2],
        'status': f[3],
        'avatar_path': f[5],
        'avatar_url': build_avatar_url(f[5])
    } for f in friends]
    return {'friends': friends_list}, 200

@app.route('/api/friend_requests', methods=['POST'])
def api_get_friend_requests():
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    requests = database.get_pending_requests(conn, user[0])
    requests_list = [{
        'id': r[0],
        'username': r[1],
        'display_name': r[3] or r[1],
        'email': r[2],
        'avatar_path': r[4],
        'avatar_url': build_avatar_url(r[4])
    } for r in requests]
    return {'requests': requests_list}, 200

@app.route('/api/profile/avatar', methods=['POST'])
@rate_limit(10, 300, scope='token')
def api_upload_avatar():
    token = request.form.get('token')
    if not token:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=token)
    if user is None:
        return {'error': 'Invalid token'}, 401
    avatar = request.files.get('avatar')
    validation_error = validate_avatar_upload(avatar)
    if validation_error:
        return {'error': validation_error}, 400

    os.makedirs(AVATAR_UPLOAD_DIR, exist_ok=True)
    old_avatar_path = get_user_avatar_path(user)
    extension = os.path.splitext(secure_filename(avatar.filename))[1].lower()
    stored_filename = f"{user[0]}-{uuid.uuid4().hex}{extension}"
    relative_path = os.path.join('static', 'uploads', 'avatars', stored_filename)
    absolute_path = os.path.join(os.getcwd(), relative_path)
    avatar.save(absolute_path)
    database.update_user_avatar(conn, user[0], relative_path)

    if old_avatar_path:
        old_absolute_path = os.path.join(os.getcwd(), old_avatar_path)
        if os.path.exists(old_absolute_path) and os.path.abspath(old_absolute_path) != os.path.abspath(absolute_path):
            try:
                os.remove(old_absolute_path)
            except OSError:
                pass

    emit('update_chat_list', namespace='/chat', to=str(user[0]))
    return {
        'message': 'Avatar updated',
        'avatar_path': relative_path,
        'avatar_url': build_avatar_url(relative_path)
    }, 200

@app.route('/api/user/<user_id>', methods=['POST'])
def api_get_user(user_id):
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    if not verify_user(data['token']):
        return {'error': 'Invalid token'}, 401
    me = database.get_user(conn, token=data['token'])
    if user_id == 'me':
        user = me
    else:
        user = database.get_user(conn, user_id=user_id)
        if user is None:
            return {'error': 'User not found'}, 404
        if not can_view_user(me[0], user[0]):
            return {'error': 'Not friends'}, 403
    return {'user': build_user_payload(user)}, 200

@app.route('/api/vapid_public_key', methods=['GET'])
def api_get_vapid_public_key():
    """Get the VAPID public key for push subscriptions."""
    return {'publicKey': VAPID_PUBLIC_KEY}, 200

@app.route('/api/push/subscribe', methods=['POST'])
def api_subscribe_push():
    """Subscribe to push notifications."""
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    if 'endpoint' not in data or 'p256dh' not in data or 'auth' not in data:
        return {'error': 'Missing subscription data'}, 400
    
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    database.create_push_subscription(
        conn, user[0], data['endpoint'], data['p256dh'], data['auth']
    )
    return {'message': 'Subscribed to push notifications'}, 200

@app.route('/api/push/unsubscribe', methods=['POST'])
def api_unsubscribe_push():
    """Unsubscribe from push notifications."""
    data = get_request_data(request)
    if not data or 'token' not in data or 'endpoint' not in data:
        return {'error': 'Invalid input'}, 400
    
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    success = database.delete_push_subscription(conn, user[0], data['endpoint'])
    if success:
        return {'message': 'Unsubscribed from push notifications'}, 200
    else:
        return {'error': 'Subscription not found'}, 404

@app.route('/api/chats', methods=['POST'])
def api_get_chats():
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    chats = database.get_chats(conn, user[0])
    for chat in chats:
        if chat.get('avatar_path'):
            chat['avatar_url'] = build_avatar_url(chat['avatar_path'])
    return {'chats': chats}, 200

@app.route('/api/groups', methods=['POST'])
@rate_limit(10, 300, scope='token')
def api_create_group():
    data = get_request_data(request)
    if not data or 'token' not in data or 'name' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    group_id = database.create_group(conn, data['name'], data.get('description'))
    database.add_group_member(conn, group_id, user[0], role='owner')
    emit('update_chat_list', namespace='/chat', to=str(user[0]))
    return {'message': 'Group created', 'group_id': group_id}, 201

@app.route('/api/groups/<group_id>/members', methods=['POST'])
@rate_limit(20, 300, scope='token')
def api_add_group_member(group_id):
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    members = database.get_group_members(conn, group_id)
    is_member = any(m['id'] == user[0] for m in members)
    if not is_member:
         return {'error': 'Not authorized'}, 403
    new_member_id = None
    try:
        if data.get('user_id') not in (None, ''):
            new_member_id = int(data['user_id'])
        elif data.get('username'):
            target_user = database.get_user(conn, user_name=normalize_username(data['username']))
            if target_user is None:
                return {'error': 'User not found'}, 404
            new_member_id = target_user[0]
        else:
            return {'error': 'user_id or username is required'}, 400
    except (TypeError, ValueError):
        return {'error': 'Invalid user_id'}, 400
    if any(m['id'] == new_member_id for m in members):
        return {'error': 'User is already in the group'}, 400
    if database.friend_status(conn, user[0], new_member_id) != 'accepted':
        return {'error': 'Only friends can be added to a group'}, 403
    database.add_group_member(conn, group_id, new_member_id)
    for member_id in get_group_member_ids(group_id):
        emit('update_chat_list', namespace='/chat', to=str(member_id))
    return {'message': 'Member added'}, 200

@app.route('/api/groups/<group_id>/members', methods=['GET'])
def api_get_group_members(group_id):
    token = request.args.get('token')
    if not token:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=token)
    if user is None:
        return {'error': 'Invalid token'}, 401
    members = database.get_group_members(conn, group_id)
    if not any(member['id'] == user[0] for member in members):
        return {'error': 'Not authorized'}, 403
    for member in members:
        if member.get('avatar_path'):
            member['avatar_url'] = build_avatar_url(member['avatar_path'])
    return {'members': members}, 200

@app.route('/api/groups/<group_id>/members/<user_id>', methods=['DELETE'])
def api_remove_group_member(group_id, user_id):
    token = request.args.get('token')
    if not token:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=token)
    if user is None:
        return {'error': 'Invalid token'}, 401
    members = database.get_group_members(conn, group_id)
    caller = next((member for member in members if member['id'] == user[0]), None)
    if caller is None:
        return {'error': 'Not authorized'}, 403
    try:
        target_user_id = int(user_id)
    except ValueError:
        return {'error': 'Invalid user_id'}, 400
    if user[0] != target_user_id and caller['role'] != 'owner':
        return {'error': 'Not authorized'}, 403
    database.remove_group_member(conn, group_id, target_user_id)
    for member_id in set(get_group_member_ids(group_id) + [target_user_id]):
        emit('update_chat_list', namespace='/chat', to=str(member_id))
    return {'message': 'Member removed'}, 200

@app.route('/api/groups/<group_id>/leave', methods=['POST'])
def api_leave_group(group_id):
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    members = database.get_group_members(conn, group_id)
    if not any(member['id'] == user[0] for member in members):
        return {'error': 'Not authorized'}, 403
    database.remove_group_member(conn, group_id, user[0])
    for member_id in set(get_group_member_ids(group_id) + [user[0]]):
        emit('update_chat_list', namespace='/chat', to=str(member_id))
    return {'message': 'Left group'}, 200

@app.route('/api/groups/<group_id>', methods=['DELETE'])
def api_delete_group(group_id):
    token = request.args.get('token')
    if not token:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=token)
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    # Check if user is owner
    members = database.get_group_members(conn, group_id)
    # member dict: id, name, email, role
    is_owner = any(m['id'] == user[0] and m['role'] == 'owner' for m in members)
    
    if not is_owner:
        return {'error': 'Not authorized'}, 403
    member_ids = [member['id'] for member in members]
    database.delete_group(conn, group_id)
    for member_id in member_ids:
        emit('update_chat_list', namespace='/chat', to=str(member_id))
    return {'message': 'Group deleted'}, 200

@app.route('/api/friends/<friend_id>', methods=['DELETE'])
def api_delete_friend(friend_id):
    token = request.args.get('token')
    if not token:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=token)
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    try:
        friend_id = int(friend_id)
    except ValueError:
        return {'error': 'Invalid friend_id'}, 400
    if database.friend_status(conn, user[0], friend_id) != 'accepted':
        return {'error': 'Friend not found'}, 404
    database.delete_friend(conn, user[0], friend_id)
    emit('update_chat_list', namespace='/chat', to=str(user[0]))
    emit('update_chat_list', namespace='/chat', to=str(friend_id))
    return {'message': 'Friend removed'}, 200

@app.route('/api/users/<user_id>/block', methods=['POST'])
@rate_limit(20, 300, scope='token')
def api_block_user(user_id):
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    try:
        target_user_id = int(user_id)
    except ValueError:
        return {'error': 'Invalid user_id'}, 400
    if target_user_id == user[0]:
        return {'error': 'Cannot block yourself'}, 400
    target_user = database.get_user(conn, user_id=target_user_id)
    if target_user is None:
        return {'error': 'User not found'}, 404
    database.block_user(conn, user[0], target_user_id)
    emit('update_chat_list', namespace='/chat', to=str(user[0]))
    emit('update_chat_list', namespace='/chat', to=str(target_user_id))
    return {'message': 'User blocked'}, 200

@app.route('/api/message/send', methods=['POST'])
@rate_limit(30, 60, scope='token')
def api_send_message():
    data = get_request_data(request)
    if not data or 'token' not in data or 'chat_id' not in data or 'content' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    is_group = data.get('is_group', False)
    chat_id = data['chat_id']
    emit_users = []

    if is_group:
        group = database.get_group(conn, group_id=chat_id)
        if group is None:
            return {'error': 'Group not found'}, 404
        # Check if user is member of the group
        members = database.get_group_members(conn, chat_id)
        emit_users = [m['id'] for m in members]
        if not any(m['id'] == user[0] for m in members):
             return {'error': 'Not a member of this group'}, 403
    else:
        dm_chat = database.get_user_dm(conn, user_id=user[0], dm_id=chat_id)
        if dm_chat is None:
            return {'error': 'Recipient not found'}, 404
        emit_users.append(dm_chat['target_id'])
        emit_users.append(user[0])
        if dm_chat['user_id'] != user[0]:
            return {'error': 'Not authorized'}, 403

    # use create_message from database module
    message_id = database.create_message(conn, user[0], chat_id, data['content'], group=is_group)
    message = database.get_message(conn, message_id)
    
    # Determine chat name for notifications
    chat_name = None
    if is_group:
        group = database.get_group(conn, group_id=chat_id)
        chat_name = group[1] if group else "Group"
    
    for user_id in emit_users:
        emit('message', message, namespace='/chat', to=str(user_id))
        # Send push notification to recipients (but not to the sender)
        if user_id != user[0]:
            # Run notification sending in a background thread
            # Pass the database path so the thread can create its own connection
            db_path = config("database_path")
            threading.Thread(
                target=background_send_message_notification,
                args=(db_path, user_id, get_user_display_name(user), data['content'], chat_name)
            ).start()
    return {'message': 'Message sent', 'message_id': message_id}, 200

@app.route('/api/messages', methods=['POST'])
def api_get_messages():
    data = get_request_data(request)
    if not data or 'token' not in data or 'chat_id' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    is_group = data.get('is_group', False)
    chat_id = data['chat_id']
    
    if is_group:
        # Check if user is member of the group
        members = database.get_group_members(conn, chat_id)
        if not any(m['id'] == user[0] for m in members):
             return {'error': 'Not a member of this group'}, 403
    
    limit = int(data.get('limit', 50))
    messages = database.get_messages(conn, chat_id=chat_id, group=is_group, limit=limit)
    return {'messages': messages}, 200

@app.route('/api/messages/<message_id>', methods=['PUT', 'DELETE'])
def api_message_operations(message_id):
    if request.method == 'PUT':
        data = get_request_data(request)
        if not data or 'token' not in data or 'content' not in data:
            return {'error': 'Invalid input'}, 400
        user = database.get_user(conn, token=data['token'])
        if user is None:
            return {'error': 'Invalid token'}, 401
        msg = database.get_message(conn, message_id)
        if not msg:
            return {'error': 'Message not found'}, 404
        if msg['author'] != user[0]:
            return {'error': 'Not authorized'}, 403
        database.update_message(conn, message_id, data['content'])
        return {'message': 'Message updated'}, 200
    elif request.method == 'DELETE':
        token = request.args.get('token')
        if not token:
            return {'error': 'Invalid input'}, 400
        user = database.get_user(conn, token=token)
        if user is None:
            return {'error': 'Invalid token'}, 401
        msg = database.get_message(conn, message_id)
        if not msg:
            return {'error': 'Message not found'}, 404
        if msg['author'] != user[0]:
            return {'error': 'Not authorized'}, 403
        database.delete_message(conn, message_id)
        return {'message': 'Message deleted'}, 200

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/')
def home():
    return render_template('home.html')

# SocketIO events
@socketio.on('authenticate', namespace='/chat')
def handle_authenticate(data):
    token = data.get('token')
    if not token:
        emit('unauthorized', {'error': 'Invalid token'})
        return
    user = database.get_user(conn, token=token)
    if user is None:
        emit('unauthorized', {'error': 'Invalid token'})
        return
    # If token is valid, store user information in session
    session['user_id'] = user[0]
    session['username'] = user[1]
    session['display_name'] = get_user_display_name(user)
    try:
        join_room(str(user[0]))  # Join a room named after the user ID
    except Exception as e:
        print("Failed to join room:", str(e))
    emit('authenticated', {'message': 'Authenticated successfully'})

@socketio.on('send_friend_request', namespace='/chat')
def handle_send_friend_request(data):
    user_id = session.get('user_id')
    if not user_id:
        emit('error', {'error': 'Not authenticated'})
        return
    friend_id = data.get('friend_id')
    if not friend_id:
        emit('error', {'error': 'Invalid input'})
        return
    # Verify friend exists
    try:
        friend_id = int(friend_id)
    except (ValueError, TypeError):
        emit('error', {'error': 'Invalid friend ID'})
        return

    if friend_id == user_id:
        emit('error', {'error': 'Cannot friend yourself'})
        return

    friend_user = database.get_user(conn, user_id=friend_id)
    if friend_user is None:
        emit('error', {'error': 'Friend not found'})
        return
    # check existing friendship status from both directions
    friend_status = database.friend_status(conn, user_id, friend_id)
    reverse_status = database.friend_status(conn, friend_id, user_id)
    if friend_status == 'accepted':
        emit('error', {'error': 'Already friends'})
        return
    elif friend_status == 'pending':
        emit('error', {'error': 'Friend request already sent'})
        return
    elif friend_status == 'blocked':
        emit('error', {'error': 'You have blocked this user'})
        return
    elif reverse_status == 'blocked':
        emit('error', {'error': 'You are blocked by this user'})
        return
    else:
        if reverse_status == 'pending':
            database.friend(conn, user_id, friend_id, status='accepted')
            emit('update_chat_list', namespace='/chat', to=str(user_id))
            emit('update_chat_list', namespace='/chat', to=str(friend_id))
            emit('friend_request_accepted', {'user_id': user_id, 'name': session.get('display_name') or session.get('username')}, namespace='/chat', to=str(friend_id))
        else:
            database.friend(conn, user_id, friend_id, status='pending')
            emit('friend_request_sent', {'message': 'Friend request sent'})

@app.route('/test')
def test():
    return render_template('test.html')

def run():
    host = config("host")
    port = config("port")
    print(f"Starting server on {host}:{port}...")
    debug = config("debug")
    if config("ssl"):
        cert = config("ssl_cert")
        key = config("ssl_key")
        if os.path.exists(cert) and os.path.exists(key):
            # hypercorn config
            hypercorn_config = Config()
            hypercorn_config.bind = [f"{host}:{port}"]
            hypercorn_config.certfile = cert
            hypercorn_config.keyfile = key
            hypercorn_config.debug = debug
            
            # Wrap Flask app with Hypercorn's WSGI Middleware
            # Flask-SocketIO works as a WSGI middleware inside 'app' already
            # Note: This mode might restrict SocketIO to long-polling as standard WSGI doesn't support WebSockets well
            wsgi_app = AsyncioWSGIMiddleware(app)
            
            asyncio.run(serve(wsgi_app, hypercorn_config))
        else:
            print("SSL is enabled but cert or key file does not exist.")
            print("Running without SSL...")
            
            hypercorn_config = Config()
            hypercorn_config.bind = [f"{host}:{port}"]
            hypercorn_config.debug = debug
            
            wsgi_app = AsyncioWSGIMiddleware(app)
            
            asyncio.run(serve(wsgi_app, hypercorn_config))
    else:
        hypercorn_config = Config()
        hypercorn_config.bind = [f"{host}:{port}"]
        hypercorn_config.debug = debug
        
        wsgi_app = AsyncioWSGIMiddleware(app)
        
        asyncio.run(serve(wsgi_app, hypercorn_config))

# idk
if __name__ == "__main__":
    run()
