from flask import Flask, request, render_template
from flask_socketio import SocketIO, emit
import database
import hashlib

database.init_database()
conn = database.create_connection()
app = Flask(__name__)
socketio = SocketIO(app)

def verify_user(token, admin_required=False):
    user = database.get_user(conn, token=token)
    if admin_required:
        return user is not None and user[5]
    else:
        return user is not None

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
    return {'message': 'Login successful', 'token': user[4]}, 200

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
    cursor.execute('UPDATE users SET password = ? WHERE email = ?', (new_hashed_password, data['email']))
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
        'name': user[1],
        'email': user[2],
        'is_admin': bool(user[5]),
        'created_at': user[6]
    }
    return {'user': user_data}, 200

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/')
def home():
    return render_template('home.html')

def run():
    app.run()

# idk
if __name__ == "__main__":
    run()