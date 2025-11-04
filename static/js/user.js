function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
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
    if(confirm("Are you sure you want to logout?")) {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
}
function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const reconfirm_password = document.getElementById('reconfirmpassword').value;
    if (password !== reconfirm_password) {
        alert('Passwords do not match!');
        return;
    }
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
    old_password = document.getElementById('old-password').value;
    new_password = document.getElementById('new-password').value;
    const token = localStorage.getItem('token');
    fetch('/api/reset_password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: token, old_password: old_password, new_password: new_password })
    }).then(response => response.json())
        .then(data => {
            if (data.message) {
                alert('Password reset successful! Please log in again.');
                logout();
            } else {
                alert('Password reset failed: ' + data.error);
            }
        });
}