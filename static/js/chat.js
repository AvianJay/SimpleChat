class ChatApp {
    constructor() {
        this.socket = null;
        this.token = localStorage.getItem('token');
        this.maxMessageLength = 2000;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.currentUser = null;
        this.currentChatId = null;
        this.chats = [];
        this.cachedUsers = new Map();
    }

    init() {
        if (!this.token) {
            window.location.href = '/login';
            return;
        }

        this.updateAppHeight();
        window.addEventListener('resize', () => this.updateAppHeight());

        this.setupDom();
        this.fetchCurrentUser()
            .then(user => {
                if (!user) {
                    window.location.href = '/login';
                    return;
                }
                this.currentUser = user;
                document.getElementById('welcome-message').innerText = `歡迎, ${user.username}`;
                this.initSocket();
                this.loadChats()
                    .then(() => {
                        // Load last visited chat from localStorage
                        const lastChat = localStorage.getItem('last_chat');
                        if (lastChat) {
                            window.location.hash = `#${lastChat}`;
                        }
                    });
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
        this.chatContainer = document.querySelector('.chat-container');
        this.mobileBackBtn = document.getElementById('mobile-back-btn');

        this.mobileBackBtn.addEventListener('click', () => {
            window.location.hash = '';
        });

        this.sendButton.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        window.addEventListener('hashchange', () => this.onHashChange());

        // Friend Management
        this.addFriendBtn = document.getElementById('add-friend-btn');
        this.friendRequestsBtn = document.getElementById('friend-requests-btn');
        this.addFriendModal = document.getElementById('add-friend-modal');
        this.friendRequestsModal = document.getElementById('friend-requests-modal');
        this.closeModals = document.querySelectorAll('.close-modal');
        this.confirmAddFriendBtn = document.getElementById('confirm-add-friend');
        this.friendIdInput = document.getElementById('friend-id-input');
        this.friendRequestsList = document.getElementById('friend-requests-list');

        this.addFriendBtn.addEventListener('click', () => this.addFriendModal.style.display = 'block');
        this.friendRequestsBtn.addEventListener('click', () => {
            this.friendRequestsModal.style.display = 'block';
            this.loadFriendRequests();
        });

        this.closeModals.forEach(btn => {
            btn.addEventListener('click', () => {
                this.addFriendModal.style.display = 'none';
                this.friendRequestsModal.style.display = 'none';
            });
        });

        window.addEventListener('click', (e) => {
            if (e.target === this.addFriendModal) this.addFriendModal.style.display = 'none';
            if (e.target === this.friendRequestsModal) this.friendRequestsModal.style.display = 'none';
        });

        this.confirmAddFriendBtn.addEventListener('click', () => this.sendFriendRequest());
    }

    async sendFriendRequest() {
        const friendId = this.friendIdInput.value.trim();
        if (!friendId) return alert('請輸入好友 ID');

        try {
            const res = await fetch('/api/friend_request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token, friend_id: friendId })
            });
            const data = await res.json();
            if (res.ok) {
                this.showToast('好友邀請已發送', '', null, "green");
                this.addFriendModal.style.display = 'none';
                this.friendIdInput.value = '';
            } else {
                this.showToast('好友邀請失敗', data.error || '發送失敗', null, "red");
            }
        } catch (e) {
            console.error(e);
            this.showToast('好友邀請失敗', e, null, "red");
        }
    }

    async loadFriendRequests() {
        try {
            const res = await fetch('/api/friend_requests', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token })
            });
            const data = await res.json();
            this.friendRequestsList.innerHTML = '';
            if (data.requests.length === 0) {
                this.friendRequestsList.innerHTML = '<li>尚無好友邀請</li>';
                return;
            }
            data.requests.forEach(req => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>${req.name} (ID: ${req.id})</span>
                    <div class="request-actions">
                        <button class="btn-accept" onclick="chatApp.acceptFriendRequest(${req.id})">接受</button>
                    </div>
                `;
                this.friendRequestsList.appendChild(li);
            });
        } catch (e) {
            console.error(e);
            this.friendRequestsList.innerHTML = '<li>載入失敗</li>';
        }
    }

    async acceptFriendRequest(friendId) {
        try {
            const res = await fetch('/api/friend_request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token, friend_id: friendId })
            });
            const data = await res.json();
            if (res.ok) {
                this.showToast('已接受好友邀請', '', null, "green");
                this.loadFriendRequests(); // Reload list
                // this.loadChats(); // Reload chats
            } else {
                this.showToast('接受好友邀請失敗', data.error || '操作失敗', null, "red");
            }
        } catch (e) {
            console.error(e);
            this.showToast('接受好友邀請失敗', e, null, "red");
        }
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

    async fetchUser(id) {
        const res = await fetch(`/api/user/${id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        const data = await res.json();
        this.cachedUsers.set(id, data.user);
        return data.user;
    }

    async getUser(id) {
        if (this.cachedUsers.has(id)) {
            return this.cachedUsers.get(id);
        }
        return await this.fetchUser(id);
    }

    initSocket() {
        this.socket = io("/chat");
        this.socket.on('connect', () => {
            this.socket.emit('authenticate', { token: this.token });
        });

        this.socket.on('authenticated', () => {
            console.log('Authenticated');
            this.loadChats();
            this.enableChatInterface(true);
        });

        this.socket.on('unauthorized', (msg) => {
            console.warn('Unauthorized', msg);
            this.handleError('認證失敗，請重新登入');
            setTimeout(() => this.redirectToLogin(), 1500);
        });

        this.socket.on('update_chat_list', () => { this.loadChats(); });

        this.socket.on('friend_request_accepted', (data) => {
            this.showToast('好友邀請', `${data.name} 接受了你的好友邀請`, () => {
                window.location.hash = `#user/${data.chat_id}`
            }, "green");
            this.loadChats();
        });

        this.socket.on('got_friend_request', (data) => {
            this.showToast('好友邀請', `${data.name} 想要加你為好友`, () => {
                this.friendRequestsModal.style.display = 'block';
                this.loadFriendRequests();
            }, "green");
        });

        this.socket.on('disconnect', () => {
            console.log('Socket disconnected');
            this.enableChatInterface(false);
        });

        this.socket.on('connect_error', (err) => {
            console.error('connect_error', err);
            this.reconnectAttempts++;
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                this.handleError('連線失敗，請檢查您的網路');
            }
        });

        this.socket.on('message', (msg) => this.displayMessage(msg, true));
    }

    async loadChats() {
        const res = await fetch('/api/chats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        const data = await res.json();
        this.chats = data.chats;
        this.chatList.innerHTML = '';
        data.chats.forEach(chat => {
            const li = document.createElement('li');
            li.textContent = chat.name;
            li.addEventListener('click', () => {
                window.location.hash = `#${chat.chat_type}/${chat.id}`;
                // Update active state
                document.querySelectorAll('#chat-list li').forEach(el => el.classList.remove('active'));
                li.classList.add('active');
            });
            this.chatList.appendChild(li);
        });
        // if hash present, trigger
        if (window.location.hash) this.onHashChange();
    }

    async onHashChange() {
        const chatType = window.location.hash.split('/')[0];
        const chatId = window.location.hash.split('/')[1];
        this.currentChatId = chatId;

        // Toggle Mobile View Class
        if (chatId) {
            this.chatContainer.classList.add('mobile-chat-active');
        } else {
            this.chatContainer.classList.remove('mobile-chat-active');
        }

        if (!chatId) {
            this.chatNameElem.innerText = '選擇聊天';
            this.messagesDiv.innerHTML = '<div class="empty-state"><p>選擇一個對話開始聊天</p></div>';
            this.enableChatInterface(false);
            return;
        }

        const chat = this.chats.find(c => String(c.id) === String(chatId));
        if (!chat) {
            // alert('Chat not found');
            return;
        }
        this.chatNameElem.innerText = chat.name;

        // Highlight active chat in list
        const listItems = this.chatList.querySelectorAll('li');
        listItems.forEach(li => {
            if (li.textContent === chat.name) li.classList.add('active');
            else li.classList.remove('active');
        });

        await this.loadMessages(chatType, chatId);
        this.enableChatInterface(true);
        // record last visited chat
        localStorage.setItem('last_chat', `${chatType}/${chatId}`);
    }

    async loadMessages(chatType, chatId) {
        const res = await fetch(`/api/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token, chat_id: chatId, is_group: chatType === 'group' })
        });
        const data = await res.json();
        this.messagesDiv.innerHTML = '';
        if (data.messages.length === 0) {
            this.messagesDiv.innerHTML = '<div class="empty-state"><p>尚無訊息</p></div>';
        } else {
            // sort messages by timestamp
            data.messages.sort((a, b) => a.timestamp - b.timestamp);
            for (const msg of data.messages) {
                await this.displayMessage(msg, false);
            }
        }
    }

    async sendMessage() {
        const chatType = window.location.hash.split('/')[0];
        const chatId = window.location.hash.split('/')[1];
        const message = this.messageInput.value.trim();
        if (!chatId) return this.handleError('請選擇聊天對象');
        if (!message) return this.handleError('請輸入訊息內容');
        if (message.length > this.maxMessageLength) return this.handleError(`訊息長度過長 (上限 ${this.maxMessageLength} 字)`);

        try {
            const res = await fetch('/api/message/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token, chat_id: chatId, content: message, is_group: chatType === 'group' })
            });
            if (!res.ok) throw new Error('send failed');
            this.messageInput.value = '';
            this.hideError();
        } catch (e) {
            this.handleError('發送失敗', e);
        }
    }

    async displayMessage(msg, notify) {
        // Remove empty state if present
        const emptyState = this.messagesDiv.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const isMe = this.currentUser && String(msg.author) === String(this.currentUser.id);
        let authorName = 'Unknown';
        let user;
        if (isMe) {
            authorName = '你';
        } else {
            user = await this.getUser(msg.author);
            authorName = user ? user.username : `${msg.author}`;
        }

        if (!this.currentChatId || String(msg.chat_id) !== String(this.currentChatId)) {
            // Message does not belong to current chat
            if (!notify) return;
            if (isMe) return;
            const chatLinkType = msg.is_group ? 'group' : 'user';
            this.showToast(authorName, msg.content, () => {
                window.location.hash = `#${chatLinkType}/${msg.chat_id}`;
            }, "blue");
            return;
        }

        const el = document.createElement('div');
        el.className = `message ${isMe ? 'outgoing' : 'incoming'}`;

        const author = document.createElement('span');
        author.className = 'message-author';
        author.textContent = authorName;

        const content = document.createElement('div');
        content.className = 'message-content';
        content.textContent = msg.content;

        el.appendChild(author);
        el.appendChild(content);

        if (msg.created_at) {
            const time = document.createElement('span');
            time.className = 'message-time';
            time.style.fontSize = '10px';
            time.style.opacity = '0.7';
            time.style.display = 'block';
            time.style.textAlign = 'right';
            time.style.marginTop = '4px';
            time.textContent = new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            el.appendChild(time);
        }

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
        setTimeout(() => {
            this.errorElem.style.display = 'none';
        }, 5000);
    }

    hideError() {
        this.errorElem.style.display = 'none';
    }

    redirectToLogin() {
        localStorage.removeItem('token');
        window.location.href = '/login';
    }

    showToast(title, message, onClick = null, color = null) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = 'toast';

        // Apply color if provided
        if (color) {
            toast.style.borderLeftColor = color;
        }

        const header = document.createElement('div');
        header.className = 'toast-header';

        const titleEl = document.createElement('div');
        titleEl.className = 'toast-title';
        titleEl.textContent = title;

        header.appendChild(titleEl);

        const msgEl = document.createElement('div');
        msgEl.className = 'toast-message';
        msgEl.textContent = message;

        const progressContainer = document.createElement('div');
        progressContainer.className = 'toast-progress';

        const progressBar = document.createElement('div');
        progressBar.className = 'toast-progress-bar';
        if (color) {
            progressBar.style.backgroundColor = color;
        } else {
            progressBar.style.backgroundColor = 'var(--primary)';
        }

        progressContainer.appendChild(progressBar);

        toast.appendChild(header);
        toast.appendChild(msgEl);
        toast.appendChild(progressContainer);

        // Click Event
        toast.addEventListener('click', () => {
            if (onClick) onClick();
            removeToast();
        });

        // Add to container
        container.appendChild(toast);

        // Auto remove after 5 seconds
        const timer = setTimeout(() => {
            removeToast();
        }, 5000);

        function removeToast() {
            clearTimeout(timer);
            toast.style.animation = 'none'; // Clear entry animation
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 300);
        }
    }

    updateAppHeight() {
        document.documentElement.style.setProperty('--app-height', `${window.innerHeight}px`);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.chatApp = new ChatApp();
    window.chatApp.init();
});
