class ChatApp {
    constructor() {
        this.socket = null;
        this.token = localStorage.getItem('token');
        this.maxMessageLength = 2000;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
    }

    init() {
        if (!this.token) {
            window.location.href = '/login';
            return;
        }

        this.setupDom();
        this.fetchCurrentUser()
            .then(user => {
                if (!user) {
                    window.location.href = '/login';
                    return;
                }
                document.getElementById('welcome-message').innerText = `歡迎, ${user.username}`;
                this.initSocket();
                this.loadChats();
            })
            .catch(() => window.location.href = '/login');
    }

    setupDom() {
        this.sendButton = document.getElementById('send-button');
        this.messageInput = document.getElementById('message-input');
        this.chatList = document.getElementById('chat-list');
        this.messagesDiv = document.getElementById('messages');
        this.chatNameElem = document.getElementById('chat-name');
        this.errorElem = document.getElementById('error-message');

        this.sendButton.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        window.addEventListener('hashchange', () => this.onHashChange());
    }

    async fetchCurrentUser() {
        const res = await fetch('/api/user/me', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        const data = await res.json();
        return data.user;
    }

    initSocket() {
        this.socket = io();
        this.socket.on('connect', () => {
            this.socket.emit('authenticate', { token: this.token });
        });

        this.socket.on('authenticated', () => {
            console.log('Authenticated');
            this.enableChatInterface(true);
        });

        this.socket.on('unauthorized', (msg) => {
            console.warn('Unauthorized', msg);
            this.handleError('認證失敗，請重新登入');
            setTimeout(() => this.redirectToLogin(), 1500);
        });

        this.socket.on('new_message', (msg) => this.displayMessage(msg));

        this.socket.on('disconnect', () => {
            console.log('Socket disconnected');
            this.enableChatInterface(false);
        });

        this.socket.on('connect_error', (err) => {
            console.error('connect_error', err);
            this.reconnectAttempts++;
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                this.handleError('無法連接到伺服器，請檢查網路或稍後再試');
            }
        });
    }

    async loadChats() {
        const res = await fetch('/api/chats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        const data = await res.json();
        this.chatList.innerHTML = '';
        data.chats.forEach(chat => {
            const li = document.createElement('li');
            li.textContent = chat.name;
            li.addEventListener('click', () => {
                window.location.hash = `#${chat.id}`;
            });
            this.chatList.appendChild(li);
        });
        // if hash present, trigger
        if (window.location.hash) this.onHashChange();
    }

    async onHashChange() {
        const chatId = window.location.hash.substring(1);
        if (!chatId) {
            this.chatNameElem.innerText = '...';
            this.messagesDiv.innerHTML = '';
            this.enableChatInterface(false);
            return;
        }

        const res = await fetch('/api/chats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        const data = await res.json();
        const chat = data.chats.find(c => String(c.id) === String(chatId));
        if (!chat) {
            alert('Chat not found');
            return;
        }
        this.chatNameElem.innerText = chat.name;
        await this.loadMessages(chatId);
        this.enableChatInterface(true);
    }

    async loadMessages(chatId) {
        const res = await fetch('/api/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token, chat_id: chatId })
        });
        const data = await res.json();
        this.messagesDiv.innerHTML = '';
        data.messages.forEach(msg => this.displayMessage(msg));
    }

    async sendMessage() {
        const chatId = window.location.hash.substring(1);
        const message = this.messageInput.value.trim();
        if (!message) return this.handleError('請輸入訊息內容');
        if (message.length > this.maxMessageLength) return this.handleError(`訊息長度不能超過 ${this.maxMessageLength} 個字元`);

        try {
            const res = await fetch('/api/message/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token, recipient_id: chatId, content: message })
            });
            if (!res.ok) throw new Error('send failed');
            this.messageInput.value = '';
            this.hideError();
        } catch (e) {
            this.handleError('發送訊息失敗，請稍後再試', e);
        }
    }

    displayMessage(msg) {
        const el = document.createElement('div');
        el.className = 'message';
        const author = document.createElement('span');
        author.className = 'message-author';
        author.textContent = `${msg.author}: `;
        const content = document.createElement('span');
        content.textContent = msg.content;
        el.appendChild(author);
        el.appendChild(content);
        this.messagesDiv.appendChild(el);
        this.messagesDiv.scrollTop = this.messagesDiv.scrollHeight;
    }

    enableChatInterface(enabled) {
        this.sendButton.disabled = !enabled;
        this.messageInput.disabled = !enabled;
        this.messageInput.placeholder = enabled ? '輸入訊息...' : '連線中斷...';
    }

    handleError(message, err = null) {
        console.error(message, err);
        this.errorElem.textContent = message;
        this.errorElem.style.display = 'block';
    }

    hideError() {
        this.errorElem.style.display = 'none';
    }

    redirectToLogin() {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }
}

// init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    const chatApp = new ChatApp();
    chatApp.init();
});
