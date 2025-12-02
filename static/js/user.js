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
                alert('登入失敗: ' + data.error);
            }
        });
}
function logout() {
    if (confirm("確定要登出嗎？")) {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
}
function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const reconfirm_password = document.getElementById('reconfirmpassword').value;
    if (password !== reconfirm_password) {
        alert('密碼不一致!');
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
                alert('註冊成功! 請登入。');
                window.location.href = '/login';
            } else {
                alert('註冊失敗: ' + data.error);
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
                alert('密碼重置成功! 請重新登入。');
                logout();
            } else {
                alert('密碼重置失敗: ' + data.error);
            }
        });
}