class ChatApp {
    constructor() {
        this.socket = null;
        this.token = localStorage.getItem('token');
        this.maxMessageLength = 2000;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.currentUser = null;
        this.currentChat = null;
        this.chats = [];
        this.cachedUsers = new Map();
        this.currentGroupMembers = [];
        this.avatarPreviewUrl = null;
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
            .then((user) => {
                if (!user) {
                    this.redirectToLogin();
                    return;
                }
                this.currentUser = user;
                this.renderCurrentUserSummary();
                this.initSocket();
                return this.loadChats();
            })
            .then(() => {
                const lastChat = localStorage.getItem('last_chat');
                if (lastChat && !window.location.hash) {
                    window.location.hash = `#${lastChat}`;
                } else {
                    this.onHashChange();
                }
            })
            .catch((error) => {
                console.error(error);
                this.redirectToLogin();
            });
    }

    setupDom() {
        this.sendButton = document.getElementById('send-button');
        this.messageInput = document.getElementById('message-input');
        this.chatList = document.getElementById('chat-list');
        this.messagesDiv = document.getElementById('messages');
        this.chatNameElem = document.getElementById('chat-name');
        this.chatMetaElem = document.getElementById('chat-meta');
        this.errorElem = document.getElementById('error-message');
        this.chatContainer = document.querySelector('.chat-container');
        this.mobileBackBtn = document.getElementById('mobile-back-btn');
        this.loadingElem = document.getElementById('loading');
        this.contextMenu = document.getElementById('chat-context-menu');

        this.avatarSettingsBtn = document.getElementById('avatar-settings-btn');
        this.addFriendBtn = document.getElementById('add-friend-btn');
        this.friendRequestsBtn = document.getElementById('friend-requests-btn');
        this.createGroupBtn = document.getElementById('create-group-btn');
        this.groupActionsBtn = document.getElementById('group-actions-btn');

        this.avatarModal = document.getElementById('avatar-modal');
        this.addFriendModal = document.getElementById('add-friend-modal');
        this.friendRequestsModal = document.getElementById('friend-requests-modal');
        this.createGroupModal = document.getElementById('create-group-modal');
        this.groupMembersModal = document.getElementById('group-members-modal');

        this.avatarFileInput = document.getElementById('avatar-file-input');
        this.avatarPreview = document.getElementById('avatar-preview');
        this.friendUsernameInput = document.getElementById('friend-username-input');
        this.friendRequestsList = document.getElementById('friend-requests-list');
        this.groupNameInput = document.getElementById('group-name-input');
        this.groupDescriptionInput = document.getElementById('group-description-input');
        this.groupMemberUsernameInput = document.getElementById('group-member-username-input');
        this.groupMembersList = document.getElementById('group-members-list');
        this.groupManageTitle = document.getElementById('group-manage-title');
        this.groupDeleteBtn = document.getElementById('delete-group-btn');
        this.groupLeaveBtn = document.getElementById('leave-group-btn');

        this.mobileBackBtn.addEventListener('click', () => {
            window.location.hash = '';
        });

        this.sendButton.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                this.sendMessage();
            }
        });

        window.addEventListener('hashchange', () => this.onHashChange());
        window.addEventListener('click', () => this.hideContextMenu());
        window.addEventListener('resize', () => this.hideContextMenu());
        document.addEventListener('scroll', () => this.hideContextMenu(), true);

        this.avatarSettingsBtn.addEventListener('click', () => {
            this.renderAvatarPreview();
            this.openModal(this.avatarModal);
        });
        this.addFriendBtn.addEventListener('click', () => this.openModal(this.addFriendModal));
        this.friendRequestsBtn.addEventListener('click', () => {
            this.openModal(this.friendRequestsModal);
            this.loadFriendRequests();
        });
        this.createGroupBtn.addEventListener('click', () => this.openModal(this.createGroupModal));
        this.groupActionsBtn.addEventListener('click', () => this.openGroupMembersModal());

        this.avatarFileInput.addEventListener('change', () => this.renderAvatarPreview());
        document.getElementById('confirm-avatar-upload').addEventListener('click', () => this.uploadAvatar());
        document.getElementById('confirm-add-friend').addEventListener('click', () => this.sendFriendRequest());
        document.getElementById('confirm-create-group').addEventListener('click', () => this.createGroup());
        document.getElementById('confirm-add-group-member').addEventListener('click', () => this.addGroupMember());
        this.groupDeleteBtn.addEventListener('click', () => this.deleteGroup());
        this.groupLeaveBtn.addEventListener('click', () => this.leaveGroup());

        document.querySelectorAll('.close-modal').forEach((button) => {
            button.addEventListener('click', () => this.closeAllModals());
        });

        window.addEventListener('click', (event) => {
            [this.avatarModal, this.addFriendModal, this.friendRequestsModal, this.createGroupModal, this.groupMembersModal].forEach((modal) => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        });
    }

    openModal(modal) {
        if (modal) {
            modal.style.display = 'block';
        }
    }

    closeAllModals() {
        [this.avatarModal, this.addFriendModal, this.friendRequestsModal, this.createGroupModal, this.groupMembersModal].forEach((modal) => {
            if (modal) {
                modal.style.display = 'none';
            }
        });
    }

    getInitials(label) {
        return (label || '?')
            .trim()
            .split(/\s+/)
            .slice(0, 2)
            .map((part) => part[0] || '')
            .join('')
            .toUpperCase();
    }

    createAvatarElement(entity, className = 'avatar') {
        const avatar = document.createElement('div');
        avatar.className = className;
        const label = entity?.display_name || entity?.name || entity?.username || '?';
        if (entity?.avatar_url) {
            const image = document.createElement('img');
            image.src = entity.avatar_url;
            image.alt = label;
            avatar.appendChild(image);
        } else {
            avatar.textContent = this.getInitials(label);
        }
        return avatar;
    }

    renderCurrentUserSummary() {
        const welcome = document.getElementById('welcome-message');
        if (!welcome || !this.currentUser) {
            return;
        }
        welcome.innerHTML = '';
        const avatar = this.createAvatarElement(this.currentUser, 'avatar avatar-sm');
        const textWrap = document.createElement('div');
        textWrap.className = 'welcome-copy';
        const name = document.createElement('div');
        name.textContent = this.currentUser.display_name;
        const username = document.createElement('div');
        username.className = 'welcome-username';
        username.textContent = `@${this.currentUser.username}`;
        textWrap.appendChild(name);
        textWrap.appendChild(username);
        welcome.appendChild(avatar);
        welcome.appendChild(textWrap);
    }

    renderAvatarPreview() {
        if (!this.avatarPreview) {
            return;
        }
        if (this.avatarPreviewUrl) {
            URL.revokeObjectURL(this.avatarPreviewUrl);
            this.avatarPreviewUrl = null;
        }
        this.avatarPreview.innerHTML = '';
        const file = this.avatarFileInput?.files?.[0];
        if (file) {
            this.avatarPreviewUrl = URL.createObjectURL(file);
            this.avatarPreview.appendChild(this.createAvatarElement({
                display_name: this.currentUser?.display_name,
                avatar_url: this.avatarPreviewUrl
            }, 'avatar avatar-xl'));
            return;
        }
        this.avatarPreview.appendChild(this.createAvatarElement(this.currentUser, 'avatar avatar-xl'));
    }

    async apiFetch(url, options = {}) {
        const response = await fetch(url, options);
        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }

        return data;
    }

    async fetchCurrentUser() {
        const data = await this.apiFetch('/api/user/me', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        this.cachedUsers.set(data.user.id, data.user);
        return data.user;
    }

    async fetchUser(id) {
        const data = await this.apiFetch(`/api/user/${id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });
        this.cachedUsers.set(id, data.user);
        return data.user;
    }

    async getUser(id) {
        if (this.cachedUsers.has(id)) {
            return this.cachedUsers.get(id);
        }
        return this.fetchUser(id);
    }

    initSocket() {
        this.socket = io('/chat');
        this.socket.on('connect', () => {
            this.socket.emit('authenticate', { token: this.token });
        });

        this.socket.on('authenticated', () => {
            this.reconnectAttempts = 0;
            this.enableChatInterface(Boolean(this.currentChat));
            this.loadChats();
        });

        this.socket.on('unauthorized', () => {
            this.handleError('登入已失效，正在返回登入頁。');
            setTimeout(() => this.redirectToLogin(), 1200);
        });

        this.socket.on('update_chat_list', async () => {
            await this.loadChats();
            if (this.currentChat?.chat_type === 'group') {
                this.loadGroupMembers().catch((error) => console.error(error));
            }
        });

        this.socket.on('friend_request_accepted', (data) => {
            this.showToast('好友已接受', `${data.name} 已接受你的好友邀請。`, null, 'green');
            this.loadChats();
        });

        this.socket.on('got_friend_request', (data) => {
            this.showToast('新的好友邀請', `${data.name} 想加你為好友。`, () => {
                this.openModal(this.friendRequestsModal);
                this.loadFriendRequests();
            }, 'green');
        });

        this.socket.on('disconnect', () => {
            this.enableChatInterface(false);
        });

        this.socket.on('connect_error', (error) => {
            console.error('connect_error', error);
            this.reconnectAttempts += 1;
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                this.handleError('即時連線失敗，請重新整理頁面。');
            }
        });

        this.socket.on('message', (message) => this.renderMessage(message, true));
    }

    async loadChats() {
        const data = await this.apiFetch('/api/chats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: this.token })
        });

        this.chats = data.chats;
        this.chatList.innerHTML = '';

        data.chats.forEach((chat) => {
            const li = document.createElement('li');
            li.dataset.chatType = chat.chat_type;
            li.dataset.chatId = chat.id;
            if (chat.user_id) {
                li.dataset.userId = chat.user_id;
            }

            const contentWrap = document.createElement('div');
            contentWrap.className = 'chat-list-item-main';
            contentWrap.appendChild(this.createAvatarElement(chat, 'avatar avatar-sm'));

            const title = document.createElement('span');
            title.className = 'chat-list-title';
            title.textContent = chat.name;
            contentWrap.appendChild(title);

            const badge = document.createElement('span');
            badge.className = `chat-badge ${chat.chat_type}`;
            badge.textContent = chat.chat_type === 'group' ? '群組' : '好友';

            li.appendChild(contentWrap);
            li.appendChild(badge);
            li.addEventListener('click', () => {
                window.location.hash = `#${chat.chat_type}/${chat.id}`;
            });
            li.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                this.openContextMenu(event, chat);
            });

            this.chatList.appendChild(li);
        });

        this.highlightActiveChat();
        if (window.location.hash) {
            await this.onHashChange();
        }
    }

    highlightActiveChat() {
        const hash = window.location.hash.replace('#', '');
        this.chatList.querySelectorAll('li').forEach((li) => {
            const key = `${li.dataset.chatType}/${li.dataset.chatId}`;
            li.classList.toggle('active', key === hash);
        });
    }

    async onHashChange() {
        const hash = window.location.hash.replace('#', '');
        this.highlightActiveChat();

        if (!hash) {
            this.currentChat = null;
            this.chatContainer.classList.remove('mobile-chat-active');
            this.chatNameElem.innerText = '選擇聊天室';
            this.chatMetaElem.innerText = '從左側選擇一位好友或群組開始聊天。';
            this.messagesDiv.innerHTML = '<div class="empty-state"><p>還沒有打開任何聊天室。</p></div>';
            this.enableChatInterface(false);
            this.groupActionsBtn.hidden = true;
            return;
        }

        const [chatType, chatId] = hash.split('/');
        const chat = this.chats.find((item) => String(item.id) === String(chatId) && item.chat_type === chatType);

        if (!chat) {
            return;
        }

        this.currentChat = chat;
        this.chatContainer.classList.toggle('mobile-chat-active', Boolean(chatId));
        this.chatNameElem.innerText = chat.name;
        this.chatMetaElem.innerText = chat.chat_type === 'group'
            ? (chat.description || '群組聊天室')
            : `@${chat.username || ''}`.trim();
        this.groupActionsBtn.hidden = chat.chat_type !== 'group';

        await this.loadMessages(chat.chat_type, chat.id);
        this.enableChatInterface(true);
        localStorage.setItem('last_chat', `${chat.chat_type}/${chat.id}`);
    }

    async loadMessages(chatType, chatId) {
        this.loadingElem.style.display = 'block';
        try {
            const data = await this.apiFetch('/api/messages', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: this.token,
                    chat_id: chatId,
                    is_group: chatType === 'group'
                })
            });

            this.messagesDiv.innerHTML = '';
            if (!data.messages.length) {
                this.messagesDiv.innerHTML = '<div class="empty-state"><p>還沒有訊息，傳送第一句吧。</p></div>';
                return;
            }

            data.messages
                .sort((a, b) => a.timestamp - b.timestamp)
                .forEach((message) => {
                    this.renderMessage(message, false);
                });
        } finally {
            this.loadingElem.style.display = 'none';
        }
    }

    async sendMessage() {
        if (!this.currentChat) {
            this.handleError('請先選擇聊天室。');
            return;
        }

        const message = this.messageInput.value.trim();
        if (!message) {
            this.handleError('訊息不能是空的。');
            return;
        }
        if (message.length > this.maxMessageLength) {
            this.handleError(`訊息不能超過 ${this.maxMessageLength} 個字元。`);
            return;
        }

        try {
            await this.apiFetch('/api/message/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: this.token,
                    chat_id: this.currentChat.id,
                    content: message,
                    is_group: this.currentChat.chat_type === 'group'
                })
            });
            this.messageInput.value = '';
            this.hideError();
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async displayMessage(message, notify) {
        const emptyState = this.messagesDiv.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }

        const isMe = this.currentUser && String(message.author) === String(this.currentUser.id);
        let authorName = this.currentUser?.display_name || '我';

        if (!isMe) {
            try {
                const user = await this.getUser(message.author);
                authorName = user ? user.display_name : `${message.author}`;
            } catch (error) {
                console.error(error);
                authorName = `${message.author}`;
            }
        }

        const currentChatId = this.currentChat ? String(this.currentChat.id) : null;
        if (!currentChatId || String(message.chat_id) !== currentChatId) {
            if (!notify || isMe) {
                return;
            }
            const chatLinkType = message.is_group ? 'group' : 'user';
            this.showToast(authorName, message.content, () => {
                window.location.hash = `#${chatLinkType}/${message.chat_id}`;
            }, 'blue');
            return;
        }

        const el = document.createElement('div');
        el.className = `message ${isMe ? 'outgoing' : 'incoming'}`;

        const author = document.createElement('span');
        author.className = 'message-author';
        author.textContent = isMe ? '我' : authorName;

        const content = document.createElement('div');
        content.className = 'message-content';
        content.textContent = message.content;

        const time = document.createElement('span');
        time.className = 'message-time';
        time.textContent = this.formatMessageTime(message.timestamp);

        el.appendChild(author);
        el.appendChild(content);
        el.appendChild(time);

        this.messagesDiv.appendChild(el);
        this.messagesDiv.scrollTop = this.messagesDiv.scrollHeight;
    }

    async renderMessage(message, notify) {
        const emptyState = this.messagesDiv.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }

        const isMe = this.currentUser && String(message.author) === String(this.currentUser.id);
        let authorUser = this.currentUser;
        let authorName = this.currentUser?.display_name || `${message.author}`;

        if (!isMe) {
            try {
                const user = await this.getUser(message.author);
                authorUser = user;
                authorName = user ? user.display_name : `${message.author}`;
            } catch (error) {
                console.error(error);
                authorUser = null;
                authorName = `${message.author}`;
            }
        }

        const currentChatId = this.currentChat ? String(this.currentChat.id) : null;
        if (!currentChatId || String(message.chat_id) !== currentChatId) {
            if (!notify || isMe) {
                return;
            }
            const chatLinkType = message.is_group ? 'group' : 'user';
            this.showToast(authorName, message.content, () => {
                window.location.hash = `#${chatLinkType}/${message.chat_id}`;
            }, 'blue');
            return;
        }

        const el = document.createElement('div');
        el.className = `message ${isMe ? 'outgoing' : 'incoming'}`;
        if (!isMe) {
            el.appendChild(this.createAvatarElement(authorUser, 'avatar avatar-sm message-avatar'));
        }

        const body = document.createElement('div');
        body.className = 'message-body';

        const author = document.createElement('span');
        author.className = 'message-author';
        author.textContent = isMe ? 'You' : authorName;

        const content = document.createElement('div');
        content.className = 'message-content';
        content.textContent = message.content;

        const time = document.createElement('span');
        time.className = 'message-time';
        time.textContent = this.formatMessageTime(message.timestamp);

        body.appendChild(author);
        body.appendChild(content);
        body.appendChild(time);
        el.appendChild(body);

        this.messagesDiv.appendChild(el);
        this.messagesDiv.scrollTop = this.messagesDiv.scrollHeight;
    }

    formatMessageTime(timestamp) {
        if (!timestamp) {
            return '';
        }
        const date = new Date(timestamp * 1000);
        const now = new Date();
        if (date.toDateString() === now.toDateString()) {
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    }

    async uploadAvatar() {
        const file = this.avatarFileInput?.files?.[0];
        if (!file) {
            this.handleError('請先選擇圖片');
            return;
        }

        const formData = new FormData();
        formData.append('token', this.token);
        formData.append('avatar', file);

        try {
            const data = await this.apiFetch('/api/profile/avatar', {
                method: 'POST',
                body: formData
            });
            this.currentUser = {
                ...this.currentUser,
                avatar_path: data.avatar_path,
                avatar_url: data.avatar_url
            };
            this.cachedUsers.set(this.currentUser.id, this.currentUser);
            this.renderCurrentUserSummary();
            this.renderAvatarPreview();
            this.avatarFileInput.value = '';
            this.closeAllModals();
            await this.loadChats();
            if (this.currentChat?.chat_type === 'group') {
                await this.loadGroupMembers();
            }
            this.showToast('頭像', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async sendFriendRequest() {
        const value = this.friendUsernameInput.value.trim();
        if (!value) {
            this.handleError('請輸入好友的 username。');
            return;
        }

        const payload = /^\d+$/.test(value)
            ? { token: this.token, friend_id: value }
            : { token: this.token, friend_username: value };

        try {
            const data = await this.apiFetch('/api/friend_request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            this.showToast('好友邀請', data.message, null, 'green');
            this.friendUsernameInput.value = '';
            this.closeAllModals();
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async loadFriendRequests() {
        try {
            const data = await this.apiFetch('/api/friend_requests', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token })
            });
            this.friendRequestsList.innerHTML = '';

            if (!data.requests.length) {
                this.friendRequestsList.innerHTML = '<li class="simple-list-empty">目前沒有待處理的好友邀請。</li>';
                return;
            }

            data.requests.forEach((request) => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <div>
                        <strong>${request.display_name}</strong>
                        <div class="list-subtext">@${request.username}</div>
                    </div>
                    <div class="request-actions">
                        <button class="btn-accept" data-user-id="${request.id}">接受</button>
                    </div>
                `;
                li.querySelector('button').addEventListener('click', () => this.acceptFriendRequest(request.id));
                this.friendRequestsList.appendChild(li);
            });
        } catch (error) {
            console.error(error);
            this.friendRequestsList.innerHTML = '<li class="simple-list-empty">載入好友邀請失敗。</li>';
        }
    }

    async acceptFriendRequest(friendId) {
        try {
            const data = await this.apiFetch('/api/friend_request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token, friend_id: friendId })
            });
            this.showToast('好友邀請', data.message, null, 'green');
            await this.loadFriendRequests();
            await this.loadChats();
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async createGroup() {
        const name = this.groupNameInput.value.trim();
        const description = this.groupDescriptionInput.value.trim();

        if (!name) {
            this.handleError('請輸入群組名稱。');
            return;
        }

        try {
            const data = await this.apiFetch('/api/groups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: this.token,
                    name,
                    description
                })
            });

            this.groupNameInput.value = '';
            this.groupDescriptionInput.value = '';
            this.closeAllModals();
            await this.loadChats();
            window.location.hash = `#group/${data.group_id}`;
            this.showToast('群組建立成功', `已建立群組「${name}」`, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async openGroupMembersModal() {
        if (!this.currentChat || this.currentChat.chat_type !== 'group') {
            return;
        }
        this.groupManageTitle.textContent = `管理群組：${this.currentChat.name}`;
        this.openModal(this.groupMembersModal);
        await this.loadGroupMembers();
    }

    async loadGroupMembers() {
        if (!this.currentChat || this.currentChat.chat_type !== 'group') {
            return;
        }

        const data = await this.apiFetch(`/api/groups/${this.currentChat.id}/members?token=${encodeURIComponent(this.token)}`);
        this.currentGroupMembers = data.members;

        const myMember = this.currentGroupMembers.find((member) => String(member.id) === String(this.currentUser.id));
        const isOwner = myMember?.role === 'owner';

        this.groupDeleteBtn.hidden = !isOwner;
        this.groupMembersList.innerHTML = '';

        this.currentGroupMembers.forEach((member) => {
            const li = document.createElement('li');

            const info = document.createElement('div');
            info.className = 'member-info';
            info.innerHTML = `
                <div class="avatar avatar-sm">${this.getInitials(member.name || member.username)}</div>
                <div><strong>${member.name || member.username}</strong>
                <div class="list-subtext">@${member.username} · ${member.role}</div>
                </div>`;

            if (member.avatar_url) {
                const avatar = info.querySelector('.avatar');
                if (avatar) {
                    avatar.innerHTML = `<img src="${member.avatar_url}" alt="${member.name || member.username}">`;
                }
            }
            li.appendChild(info);

            if (isOwner && String(member.id) !== String(this.currentUser.id)) {
                const removeButton = document.createElement('button');
                removeButton.className = 'btn-danger-inline';
                removeButton.textContent = '移除';
                removeButton.addEventListener('click', () => this.removeGroupMember(member.id));
                li.appendChild(removeButton);
            }

            this.groupMembersList.appendChild(li);
        });
    }

    async addGroupMember() {
        if (!this.currentChat || this.currentChat.chat_type !== 'group') {
            return;
        }

        const username = this.groupMemberUsernameInput.value.trim();
        if (!username) {
            this.handleError('請輸入要加入群組的 username。');
            return;
        }

        try {
            const data = await this.apiFetch(`/api/groups/${this.currentChat.id}/members`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: this.token,
                    username
                })
            });
            this.groupMemberUsernameInput.value = '';
            await this.loadGroupMembers();
            await this.loadChats();
            this.showToast('群組成員', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async removeGroupMember(userId) {
        if (!this.currentChat || this.currentChat.chat_type !== 'group') {
            return;
        }

        try {
            const data = await this.apiFetch(`/api/groups/${this.currentChat.id}/members/${userId}?token=${encodeURIComponent(this.token)}`, {
                method: 'DELETE'
            });
            await this.loadGroupMembers();
            await this.loadChats();
            this.showToast('群組成員', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    openContextMenu(event, chat) {
        if (!this.contextMenu) {
            return;
        }

        const actions = [];
        if (chat.chat_type === 'user' && chat.user_id) {
            actions.push({
                label: '解除好友',
                className: 'danger',
                onClick: () => this.removeFriend(chat)
            });
            actions.push({
                label: '封鎖',
                className: 'danger',
                onClick: () => this.blockUser(chat)
            });
        }
        if (chat.chat_type === 'group') {
            actions.push({
                label: '離開群組',
                className: 'danger',
                onClick: () => this.leaveGroupFromChat(chat)
            });
        }

        if (!actions.length) {
            return;
        }

        this.contextMenu.innerHTML = '';
        actions.forEach((action) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.textContent = action.label;
            button.className = action.className || '';
            button.addEventListener('click', async () => {
                this.hideContextMenu();
                await action.onClick();
            });
            this.contextMenu.appendChild(button);
        });

        this.contextMenu.hidden = false;
        this.contextMenu.style.left = `${event.clientX}px`;
        this.contextMenu.style.top = `${event.clientY}px`;
    }

    hideContextMenu() {
        if (this.contextMenu) {
            this.contextMenu.hidden = true;
        }
    }

    async removeFriend(chat = this.currentChat) {
        if (!chat || chat.chat_type !== 'user' || !chat.user_id) {
            return;
        }
        if (!confirm(`解除好友：${chat.name}？`)) {
            return;
        }

        try {
            const data = await this.apiFetch(`/api/friends/${chat.user_id}?token=${encodeURIComponent(this.token)}`, {
                method: 'DELETE'
            });
            if (this.currentChat && String(this.currentChat.id) === String(chat.id) && this.currentChat.chat_type === 'user') {
                window.location.hash = '';
            }
            await this.loadChats();
            this.showToast('好友', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async blockUser(chat = this.currentChat) {
        if (!chat || chat.chat_type !== 'user' || !chat.user_id) {
            return;
        }
        if (!confirm(`封鎖使用者：${chat.name}？`)) {
            return;
        }

        try {
            const data = await this.apiFetch(`/api/users/${chat.user_id}/block`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token })
            });
            if (this.currentChat && String(this.currentChat.id) === String(chat.id) && this.currentChat.chat_type === 'user') {
                window.location.hash = '';
            }
            await this.loadChats();
            this.showToast('使用者', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async leaveGroupFromChat(chat) {
        if (!chat || chat.chat_type !== 'group') {
            return;
        }
        if (!confirm(`離開群組：${chat.name}？`)) {
            return;
        }

        try {
            const data = await this.apiFetch(`/api/groups/${chat.id}/leave`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token })
            });
            if (this.currentChat && String(this.currentChat.id) === String(chat.id) && this.currentChat.chat_type === 'group') {
                window.location.hash = '';
            }
            await this.loadChats();
            this.showToast('蝢斤?', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async leaveGroup() {
        if (!this.currentChat || this.currentChat.chat_type !== 'group') {
            return;
        }

        try {
            const data = await this.apiFetch(`/api/groups/${this.currentChat.id}/leave`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: this.token })
            });
            this.closeAllModals();
            window.location.hash = '';
            await this.loadChats();
            this.showToast('群組', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    async deleteGroup() {
        if (!this.currentChat || this.currentChat.chat_type !== 'group') {
            return;
        }

        try {
            const data = await this.apiFetch(`/api/groups/${this.currentChat.id}?token=${encodeURIComponent(this.token)}`, {
                method: 'DELETE'
            });
            this.closeAllModals();
            window.location.hash = '';
            await this.loadChats();
            this.showToast('群組', data.message, null, 'green');
        } catch (error) {
            this.handleError(error.message, error);
        }
    }

    enableChatInterface(enabled) {
        this.sendButton.disabled = !enabled;
        this.messageInput.disabled = !enabled;
        this.messageInput.placeholder = enabled ? '輸入訊息...' : '請先選擇聊天室...';
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
        if (!container) {
            return;
        }

        const toast = document.createElement('div');
        toast.className = 'toast';
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
        progressBar.style.backgroundColor = color || 'var(--primary)';
        progressContainer.appendChild(progressBar);

        toast.appendChild(header);
        toast.appendChild(msgEl);
        toast.appendChild(progressContainer);

        const removeToast = () => {
            clearTimeout(timer);
            toast.style.animation = 'none';
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 300);
        };

        toast.addEventListener('click', () => {
            if (onClick) {
                onClick();
            }
            removeToast();
        });

        container.appendChild(toast);

        const timer = setTimeout(() => {
            removeToast();
        }, 5000);
    }

    updateAppHeight() {
        document.documentElement.style.setProperty('--app-height', `${window.innerHeight}px`);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.chatApp = new ChatApp();
    window.chatApp.init();

    if (window.pushNotifications) {
        window.pushNotifications.init().catch((error) => {
            console.error('Failed to initialize push notifications:', error);
        });
    }
});
