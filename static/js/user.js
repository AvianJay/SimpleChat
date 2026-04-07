const USERNAME_PATTERN = /^[a-z0-9._-]{3,20}$/;
const THEME_STORAGE_KEY = 'theme_preference';
const THEME_TOGGLE_ICON_MARKUP = `
    <span class="theme-toggle__surface" aria-hidden="true">
        <span class="theme-toggle__sky"></span>
        <span class="theme-toggle__halo"></span>
        <span class="theme-toggle__spark theme-toggle__spark--1"></span>
        <span class="theme-toggle__spark theme-toggle__spark--2"></span>
        <span class="theme-toggle__spark theme-toggle__spark--3"></span>
        <svg class="theme-toggle__icon theme-toggle__icon--sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="4.5"></circle>
            <path d="M12 2.75v2.1"></path>
            <path d="M12 19.15v2.1"></path>
            <path d="M4.75 12h2.1"></path>
            <path d="M17.15 12h2.1"></path>
            <path d="M6.88 6.88l1.48 1.48"></path>
            <path d="M15.64 15.64l1.48 1.48"></path>
            <path d="M6.88 17.12l1.48-1.48"></path>
            <path d="M15.64 8.36l1.48-1.48"></path>
        </svg>
        <svg class="theme-toggle__icon theme-toggle__icon--moon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M15.9 3.9a8.7 8.7 0 1 0 4.2 15.8A9.8 9.8 0 0 1 15.9 3.9Z" fill="currentColor"></path>
        </svg>
    </span>
    <span class="sr-only theme-toggle__label"></span>
`;

function getPreferredTheme() {
    const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    if (savedTheme === 'light' || savedTheme === 'dark') {
        return savedTheme;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function ensureThemeToggleMarkup(button) {
    if (button.dataset.themeToggleReady === 'true') {
        return;
    }
    button.innerHTML = THEME_TOGGLE_ICON_MARKUP;
    button.dataset.themeToggleReady = 'true';
}

function pulseThemeToggle(button, nextTheme) {
    button.classList.remove('theme-toggle--pulse');
    button.dataset.themeTransition = nextTheme === 'dark' ? 'to-dark' : 'to-light';
    void button.offsetWidth;
    button.classList.add('theme-toggle--pulse');
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
        ensureThemeToggleMarkup(button);
        const nextTheme = theme === 'dark' ? 'light' : 'dark';
        const label = `Switch to ${nextTheme} mode`;
        button.dataset.themeState = theme;
        button.setAttribute('aria-label', label);
        button.setAttribute('title', label);
        const hiddenLabel = button.querySelector('.theme-toggle__label');
        if (hiddenLabel) {
            hiddenLabel.textContent = label;
        }
    });
}

function initializeThemeToggle() {
    applyTheme(getPreferredTheme());
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
        if (button.dataset.themeToggleBound === 'true') {
            return;
        }
        button.dataset.themeToggleBound = 'true';
        button.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
            const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
            localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
            pulseThemeToggle(button, nextTheme);
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
