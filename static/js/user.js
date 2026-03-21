const USERNAME_PATTERN = /^[a-z0-9._-]{3,20}$/;

function login() {
    const username = document.getElementById('username').value.trim().toLowerCase();
    const password = document.getElementById('password').value;

    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.token) {
                localStorage.setItem('token', data.token);
                window.location.href = '/chat';
            } else {
                alert(`登入失敗: ${data.error}`);
            }
        });
}

function logout() {
    if (confirm('確定要登出嗎？')) {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
}

function register() {
    const username = document.getElementById('username').value.trim().toLowerCase();
    const displayName = document.getElementById('display_name').value.trim();
    const password = document.getElementById('password').value;
    const reconfirmPassword = document.getElementById('reconfirmpassword').value;
    const email = document.getElementById('email').value.trim();

    if (!USERNAME_PATTERN.test(username)) {
        alert('username 只能使用 3-20 個小寫英文字母、數字、.、_、-');
        return;
    }

    if (password !== reconfirmPassword) {
        alert('兩次輸入的密碼不一致');
        return;
    }

    fetch('/api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username,
            display_name: displayName,
            password,
            email
        })
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.message) {
                alert('註冊成功，請重新登入。');
                window.location.href = '/login';
            } else {
                alert(`註冊失敗: ${data.error}`);
            }
        });
}

function resetPassword() {
    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;
    const token = localStorage.getItem('token');

    fetch('/api/reset_password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            token,
            old_password: oldPassword,
            new_password: newPassword
        })
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.message) {
                alert('密碼已更新，請重新登入。');
                logout();
            } else {
                alert(`密碼更新失敗: ${data.error}`);
            }
        });
}
