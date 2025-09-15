from flask import Flask, request, render_template
import database
import hashlib

database.init_database()
conn = database.create_connection()
app = Flask(__name__)

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        data = get_request_data(request)
        if not data or 'name' not in data or 'email' not in data or 'password' not in data:
            return {'error': 'Invalid input'}, 400
        user_id = database.create_user(conn, data['name'], data['email'], data['password'])
        return {'message': 'User registered', 'user_id': user_id}, 201

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        data = get_request_data(request)
        if not data or 'email' not in data or 'password' not in data:
            return {'error': 'Invalid input'}, 400
        user = database.get_user(conn, email=data['email'])
        if user and user[3] == hashlib.sha256(data['password'].encode()).hexdigest():
            return {'message': 'Login successful', 'token': user[4]}, 200
        return {'error': 'Invalid credentials'}, 401

@app.route('/')
def home():
    return render_template('index.html')

def run():
    app.run()

# idk
if __name__ == "__main__":
    run()