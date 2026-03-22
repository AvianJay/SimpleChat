const USERNAME_PATTERN = /^[a-z0-9._-]{3,20}$/;
const THEME_STORAGE_KEY = 'theme_preference';

function getPreferredTheme() {
    const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    if (savedTheme === 'light' || savedTheme === 'dark') {
        return savedTheme;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
        button.textContent = theme === 'dark' ? '淺色模式' : '深色模式';
        button.setAttribute('aria-label', theme === 'dark' ? '切換到淺色模式' : '切換到深色模式');
    });
}

function initializeThemeToggle() {
    applyTheme(getPreferredTheme());
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
        button.addEventListener('click', () => {
            const nextTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
            applyTheme(nextTheme);
        });
    });
}

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
            } else if (data.error === 'Email not verified') {
                if (confirm('電子郵件尚未驗證。要重寄驗證信嗎？')) {
                    resendVerificationEmail({ username });
                }
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
                const suffix = data.verification_email_sent ? '請到信箱完成驗證後再登入。' : `驗證信未送出: ${data.mail_error || 'unknown error'}`;
                alert(`註冊成功。${suffix}`);
                window.location.href = '/login';
            } else {
                alert(`註冊失敗: ${data.error}`);
            }
        });
}

function resendVerificationEmail(payload) {
    fetch('/api/verify_email/resend', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.message) {
                alert(data.message);
            } else {
                alert(`重寄驗證信失敗: ${data.error}`);
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

document.addEventListener('DOMContentLoaded', () => {
    initializeThemeToggle();
});
