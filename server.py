from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
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
    friend_status = database.friend_status(conn, user[0], data['friend_id'])
    if friend_status == 'accepted':
        return {'error': 'Already friends'}, 400
    elif friend_status == 'pending':
        return {'error': 'Friend request already sent'}, 400
    elif friend_status == 'blocked':
        return {'error': 'You are blocked by this user'}, 400
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

@app.route('/api/user/<user_id>', methods=['POST'])
def api_get_user(user_id):
    data = get_request_data(request)
    if not data or 'token' not in data:
        return {'error': 'Invalid input'}, 400
    if not verify_user(data['token']):
        return {'error': 'Invalid token'}, 401
    if user_id == 'me':
        user = database.get_user(conn, token=data['token'])
    else:
        user = database.get_user(conn, user_id=user_id)
    if user is None:
        return {'error': 'User not found'}, 404
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

@app.route('/api/message/send', methods=['POST'])
def api_send_message():
    data = get_request_data(request)
    if not data or 'token' not in data or 'recipient_id' not in data or 'content' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    recipient = database.get_user(conn, user_id=data['recipient_id'])
    if recipient is None:
        return {'error': 'Recipient not found'}, 404
    # use create_message from database module
    message_id = database.create_message(conn, user[0], recipient[0], data['content'], group=False)
    return {'message': 'Message sent', 'message_id': message_id}, 200

@app.route('/api/messages', methods=['POST'])
def api_get_messages():
    data = get_request_data(request)
    if not data or 'token' not in data or 'chat_id' not in data:
        return {'error': 'Invalid input'}, 400
    user = database.get_user(conn, token=data['token'])
    if user is None:
        return {'error': 'Invalid token'}, 401
    limit = int(data.get('limit', 50))
    messages = database.get_messages(conn, chat_id=data['chat_id'], limit=limit)
    return {'messages': messages}, 200

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
        'created_at': database.get_message(conn, message_id)[6]
    }
    emit('new_message', message_data, room=str(recipient_id))
    emit('new_message', message_data)  # also emit to sender

@app.route('/test')
def test():
    return render_template('test.html')

def run():
    if config("ssl"):
        if os.path.exists(config("ssl_cert")) or not os.path.exists(config("ssl_key")):
            context = (config("ssl_cert"), config("ssl_key"))
            app.run(host=config("host"), port=config("port"), ssl_context=context, debug=config("debug"))
        else:
            print("SSL is enabled but cert or key file does not exist.")
            print("Running without SSL...")
            app.run(host=config("host"), port=config("port"), debug=config("debug"))
    else:
        app.run(host=config("host"), port=config("port"), debug=config("debug"))

# idk
if __name__ == "__main__":
    run()