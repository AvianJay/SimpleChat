from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit, join_room
from flask import session
import database
import hashlib
import os
from config import config

database.init_database(config("database_path"))
conn = database.create_connection(config("database_path"))
app = Flask(__name__)
# secret key required for flask session and socketio session management
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
# manage_session=True lets Flask-SocketIO use Flask's session inside events
socketio = SocketIO(app, manage_session=True)

def verify_user(token, admin_required=False):
    user = database.get_user(conn, token=token)
    if user is None:
        return False
    if admin_required:
        # user row: id, name, email, password, role, token, created_at
        return user[4] == 'admin'
    return True

def get_request_data(request):
    if request.method == 'POST':
        reqdata = request.get_json() or request.form.copy()
    else:
        reqdata = request.args.copy()
    return reqdata

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    data = get_request_data(request)
    if not data or 'username' not in data or 'email' not in data or 'password' not in data:
        return {'error': 'Invalid input'}, 400
    if database.get_user(conn, email=data['email']) is not None:
        return {'error': 'Email already registered'}, 400
    if database.get_user(conn, user_name=data['username']) is not None:
        return {'error': 'Username already taken'}, 400
    user_id = database.create_user(conn, data['username'], data['email'], data['password'])
    return {'message': 'User registered', 'user_id': user_id}, 201

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = get_request_data(request)
    if not data or 'username' not in data or 'password' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, user_name=data['username'])
    if user is None:
        return {'error': 'User not found'}, 404
    hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
    if user[3] != hashed_password:
        return {'error': 'Incorrect password'}, 401
    return {'message': 'Login successful', 'token': user[5]}, 200

@app.route('/api/reset_password', methods=['POST'])
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
def api_friend_request():
    data = get_request_data(request)
    if not data or 'token' not in data or 'friend_id' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    # check if friend_id exists
    try:
        friend_id = int(data['friend_id'])
    except (ValueError, TypeError):
        return {'error': 'Invalid friend_id'}, 400
    if friend_id == user[0]:
        return {'error': 'Cannot friend yourself'}, 400
    friend_user = database.get_user(conn, user_id=friend_id)
    if friend_user is None:
        return {'error': 'Friend not found'}, 404
    # check existing friendship status
    friend_status = database.friend_status(conn, user[0], data['friend_id'])
    if friend_status == 'accepted':
        return {'error': 'Already friends'}, 400
    elif friend_status == 'pending':
        return {'error': 'Friend request already sent'}, 400
    elif friend_status == 'blocked':
        return {'error': 'You are blocked by this user'}, 400
    else:
        # check if target user is already sent a friend request
        if database.friend_status(conn, data['friend_id'], user[0]) == 'pending':
            # update the status to accepted
            database.friend(conn, user[0], data['friend_id'], status='accepted')
            # database.friend(conn, data['friend_id'], user[0], status='accepted')
            return {'message': 'Friend request accepted'}, 200
        else:
            database.friend(conn, user[0], data['friend_id'], status='pending')
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
    friends_list = [{'id': f[0], 'name': f[1], 'email': f[2], 'status': f[3]} for f in friends]
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
    requests_list = [{'id': r[0], 'name': r[1], 'email': r[2]} for r in requests]
    return {'requests': requests_list}, 200

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
        # check if user is friend of me
        if user[0] not in [f[0] for f in database.get_friends(conn, me[0])]:
            return {'error': 'Not friends'}, 403
    user_data = {
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'role': user[4],
        'created_at': user[6]
    }
    return {'user': user_data}, 200

@app.route('/api/chats', methods=['POST'])
def api_get_chats():
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    chats = database.get_chats(conn, user[0])
    return {'chats': chats}, 200

@app.route('/api/groups', methods=['POST'])
def api_create_group():
    data = get_request_data(request)
    if not data or 'token' not in data or 'name' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    group_id = database.create_group(conn, data['name'], data.get('description'))
    database.add_group_member(conn, group_id, user[0], role='owner')
    return {'message': 'Group created', 'group_id': group_id}, 201

@app.route('/api/groups/<group_id>/members', methods=['POST'])
def api_add_group_member(group_id):
    data = get_request_data(request)
    if not data or 'token' not in data or 'user_id' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    members = database.get_group_members(conn, group_id)
    is_member = any(m[0] == user[0] for m in members)
    if not is_member:
         return {'error': 'Not authorized'}, 403
    try:
        new_member_id = int(data['user_id'])
    except ValueError:
        return {'error': 'Invalid user_id'}, 400
    database.add_group_member(conn, group_id, new_member_id)
    return {'message': 'Member added'}, 200

@app.route('/api/groups/<group_id>/members/<user_id>', methods=['DELETE'])
def api_remove_group_member(group_id, user_id):
    token = request.args.get('token')
    if not token:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=token)
    if user is None:
        return {'error': 'Invalid token'}, 401
    try:
        target_user_id = int(user_id)
    except ValueError:
        return {'error': 'Invalid user_id'}, 400
    database.remove_group_member(conn, group_id, target_user_id)
    return {'message': 'Member removed'}, 200

@app.route('/api/groups/<group_id>/leave', methods=['POST'])
def api_leave_group(group_id):
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    database.remove_group_member(conn, group_id, user[0])
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
    # member tuple: id, name, email, role
    is_owner = any(m[0] == user[0] and m[3] == 'owner' for m in members)
    
    if not is_owner:
        return {'error': 'Not authorized'}, 403
        
    database.delete_group(conn, group_id)
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
        
    database.delete_friend(conn, user[0], friend_id)
    return {'message': 'Friend removed'}, 200

@app.route('/api/message/send', methods=['POST'])
def api_send_message():
    data = get_request_data(request)
    if not data or 'token' not in data or 'recipient_id' not in data or 'content' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    
    is_group = data.get('is_group', False)
    recipient_id = data['recipient_id']

    if is_group:
        group = database.get_group(conn, group_id=recipient_id)
        if group is None:
            return {'error': 'Group not found'}, 404
        # Check if user is member of the group
        members = database.get_group_members(conn, recipient_id)
        if not any(m[0] == user[0] for m in members):
             return {'error': 'Not a member of this group'}, 403
    else:
        recipient = database.get_user_dm(conn, user_id=user[0], dm_id=recipient_id)
        if recipient is None:
            return {'error': 'Recipient not found'}, 404
        if recipient['user_id'] != user[0]:
            return {'error': 'Not authorized'}, 403

    # use create_message from database module
    message_id = database.create_message(conn, user[0], recipient_id, data['content'], group=is_group)
    message = database.get_message(conn, message_id)
    emit('message', message, namespace='/chat', to=recipient_id)
    emit('message', message, namespace='/chat', to=user[0])
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
        if not any(m[0] == user[0] for m in members):
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
        if msg[1] != user[0]:
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
        if msg[1] != user[0]:
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
@socketio.on('authenticate')
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
    try:
        join_room(str(user[0]))  # Join a room named after the user ID
    except Exception as e:
        print("Failed to join room:", str(e))
    emit('authenticated', {'message': 'Authenticated successfully'})

@socketio.on('send_message')
def handle_send_message(data):
    user_id = session.get('user_id')
    if not user_id:
        emit('error', {'error': 'Not authenticated'})
        return
    recipient_id = data.get('recipient_id')
    content = data.get('content')
    if not recipient_id or not content:
        emit('error', {'error': 'Invalid input'})
        return
    # Verify recipient exists
    try:
        recipient_id = int(recipient_id)
    except (ValueError, TypeError):
        emit('error', {'error': 'Invalid recipient ID'})
        return

    recipient = database.get_user(conn, user_id=recipient_id)
    if recipient is None:
        emit('error', {'error': 'Recipient not found'})
        return
    message_id = database.create_message(conn, user_id, recipient_id, content, group=False)
    message_data = {
        'id': message_id,
        'author': user_id,
        'chat_id': recipient_id,
        'is_group': False,
        'content': content,
        'edited': False,
        'created_at': database.get_messages(conn, message_id)[6]
    }
    emit('new_message', message_data, to=str(recipient_id))
    emit('new_message', message_data, to=str(user_id))  # also emit to sender

@socketio.on('send_friend_request')
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
    # check existing friendship status
    friend_status = database.friend_status(conn, user_id, friend_id)
    if friend_status == 'accepted':
        emit('error', {'error': 'Already friends'})
        return
    elif friend_status == 'pending':
        emit('error', {'error': 'Friend request already sent'})
        return
    elif friend_status == 'blocked':
        emit('error', {'error': 'You are blocked by this user'})
        return
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
            context = (cert, key)
            socketio.run(app, host=host, port=port, ssl_context=context, debug=debug)
        else:
            print("SSL is enabled but cert or key file does not exist.")
            print("Running without SSL...")
            socketio.run(app, host=host, port=port, debug=debug)
    else:
        socketio.run(app, host=host, port=port, debug=debug)

# idk
if __name__ == "__main__":
    run()