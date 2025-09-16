function login() {
    username = document.getElementById('username').value;
    password = document.getElementById('password').value;
    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username: username, password: password })
    }).then(response => response.json())
        .then(data => {
            if (data.token) {
                localStorage.setItem('token', data.token);
                window.location.href = '/chat';
            } else {
                alert('Login failed: ' + data.error);
            }
        });
}
function logout() {
    localStorage.removeItem('token');
    window.location.href = '/login';
}
function register() {
    username = document.getElementById('username').value;
    password = document.getElementById('password').value;
    email = document.getElementById('email').value;
    fetch('/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username: username, password: password, email: email })
    }).then(response => response.json())
        .then(data => {
            if (data.message) {
                alert('Registration successful! Please log in.');
                window.location.href = '/login';
            } else {
                alert('Registration failed: ' + data.error);
            }
        });
}
function resetPassword() {
    // todo
}