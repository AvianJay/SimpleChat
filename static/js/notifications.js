// Client-side push notification handling

let pushSubscription = null;

// Convert VAPID public key from base64url to Uint8Array
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
    
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) {
        console.log('Service Workers not supported');
        return null;
    }
    
    try {
        const registration = await navigator.serviceWorker.register('/static/sw.js');
        console.log('Service Worker registered:', registration);
        return registration;
    } catch (error) {
        console.error('Service Worker registration failed:', error);
        return null;
    }
}

async function subscribeToPushNotifications() {
    if (!('PushManager' in window)) {
        console.log('Push notifications not supported');
        return false;
    }
    
    try {
        // Register service worker first
        const registration = await registerServiceWorker();
        if (!registration) {
            return false;
        }
        
        // Wait for service worker to be ready
        await navigator.serviceWorker.ready;
        
        // Get VAPID public key from server
        const response = await fetch('/api/vapid_public_key');
        const data = await response.json();
        const vapidPublicKey = data.publicKey;
        
        // Subscribe to push notifications
        const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(vapidPublicKey)
        });
        
        pushSubscription = subscription;
        console.log('Push subscription:', subscription);
        
        // Send subscription to server
        const token = localStorage.getItem('token');
        if (!token) {
            console.error('No token found');
            return false;
        }
        
        const subscriptionJson = subscription.toJSON();
        const saveResponse = await fetch('/api/push/subscribe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                token: token,
                endpoint: subscriptionJson.endpoint,
                p256dh: subscriptionJson.keys.p256dh,
                auth: subscriptionJson.keys.auth
            })
        });
        
        if (saveResponse.ok) {
            console.log('Push subscription saved to server');
            return true;
        } else {
            console.error('Failed to save push subscription to server');
            return false;
        }
    } catch (error) {
        console.error('Error subscribing to push notifications:', error);
        return false;
    }
}

async function unsubscribeFromPushNotifications() {
    if (!pushSubscription) {
        console.log('No active push subscription');
        return false;
    }
    
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            console.error('No token found');
            return false;
        }
        
        const subscriptionJson = pushSubscription.toJSON();
        
        // Remove subscription from server
        const response = await fetch('/api/push/unsubscribe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                token: token,
                endpoint: subscriptionJson.endpoint
            })
        });
        
        // Unsubscribe locally
        await pushSubscription.unsubscribe();
        pushSubscription = null;
        
        if (response.ok) {
            console.log('Unsubscribed from push notifications');
            return true;
        } else {
            console.error('Failed to remove subscription from server');
            return false;
        }
    } catch (error) {
        console.error('Error unsubscribing from push notifications:', error);
        return false;
    }
}

async function checkPushNotificationStatus() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        return 'unsupported';
    }
    
    try {navigator.serviceWorker
        const registration = await registerServiceWorker();
        const subscription = await registration.pushManager.getSubscription();
        
        if (subscription) {
            pushSubscription = subscription;
            return 'subscribed';
        } else {
            return 'unsubscribed';
        }
    } catch (error) {
        console.error('Error checking push notification status:', error);
        return 'error';
    }
}

async function requestNotificationPermission() {
    if (!('Notification' in window)) {
        console.log('Notifications not supported');
        return 'unsupported';
    }
    
    if (Notification.permission === 'granted') {
        return 'granted';
    } else if (Notification.permission === 'denied') {
        return 'denied';
    } else {
        const permission = await Notification.requestPermission();
        return permission;
    }
}

// Initialize notifications when the page loads
async function initNotifications() {
    const permission = await requestNotificationPermission();
    
    if (permission === 'granted') {
        const status = await checkPushNotificationStatus();
        
        if (status === 'unsubscribed') {
            // Auto-subscribe if permission is granted but not subscribed
            await subscribeToPushNotifications();
        } else if (status === 'subscribed') {
            console.log('Already subscribed to push notifications');
        }
    } else {
        console.log('Notification permission:', permission);
    }
}

// Export functions for use in other scripts
window.pushNotifications = {
    init: initNotifications,
    subscribe: subscribeToPushNotifications,
    unsubscribe: unsubscribeFromPushNotifications,
    checkStatus: checkPushNotificationStatus,
    requestPermission: requestNotificationPermission
};
