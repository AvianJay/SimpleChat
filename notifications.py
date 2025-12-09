import json
from pywebpush import webpush, WebPushException
from config import config
import database
import os
import tempfile
import base64
from py_vapid import Vapid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# VAPID keys should be stored securely
VAPID_PRIVATE_KEY = None
VAPID_PUBLIC_KEY = None
VAPID_PUBLIC_KEY_BASE64URL = None
VAPID_CLAIMS = {
    "sub": "mailto:admin@simplechat.local"
}

def init_vapid_keys():
    """Initialize VAPID keys from config or environment variables."""
    global VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY, VAPID_PUBLIC_KEY_BASE64URL
    
    # Try to get from environment variables first
    VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY')
    VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY')
    
    # If not in environment, try to get from config
    if not VAPID_PRIVATE_KEY:
        VAPID_PRIVATE_KEY = config('vapid_private_key')
    if not VAPID_PUBLIC_KEY:
        VAPID_PUBLIC_KEY = config('vapid_public_key')
    
    # If still not found, generate new keys
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        vapid = Vapid()
        vapid.generate_keys()
        
        # Save to temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
            temp_priv = f.name
            vapid.save_key(temp_priv)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
            temp_pub = f.name
            vapid.save_public_key(temp_pub)
        
        try:
            with open(temp_priv, 'r') as pem_file:
                VAPID_PRIVATE_KEY = pem_file.read()
            
            with open(temp_pub, 'r') as pem_file:
                VAPID_PUBLIC_KEY = pem_file.read()
            
            # Save to config
            config('vapid_private_key', VAPID_PRIVATE_KEY, mode='w')
            config('vapid_public_key', VAPID_PUBLIC_KEY, mode='w')
            print("Generated new VAPID keys and saved to config")
        finally:
            # Clean up temporary files
            os.unlink(temp_priv)
            os.unlink(temp_pub)
    
    # Load the private key using cryptography
    private_key = serialization.load_pem_private_key(
        VAPID_PRIVATE_KEY.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Get the public key from the private key
    public_key = private_key.public_key()
    
    # Extract the raw public key bytes (65 bytes for uncompressed P-256)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Convert to base64url format (used by browser Push API)
    VAPID_PUBLIC_KEY_BASE64URL = base64.urlsafe_b64encode(public_key_bytes).decode('utf-8').rstrip('=')
    
    return VAPID_PUBLIC_KEY_BASE64URL

def send_push_notification(subscription_info, notification_data):
    """
    Send a push notification to a single subscription.
    
    Args:
        subscription_info: Dictionary with 'endpoint', 'p256dh', and 'auth' keys
        notification_data: Dictionary with notification title, body, etc.
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Build subscription object in the format pywebpush expects
        subscription = {
            "endpoint": subscription_info['endpoint'],
            "keys": {
                "p256dh": subscription_info['p256dh'],
                "auth": subscription_info['auth']
            }
        }
        
        # Send the notification
        webpush(
            subscription_info=subscription,
            data=json.dumps(notification_data),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=VAPID_CLAIMS
        )
        return True
    except WebPushException as e:
        print(f"WebPush failed: {e}")
        # If subscription is invalid (410 Gone), we should remove it
        if e.response and e.response.status_code == 410:
            return 'gone'
        return False
    except Exception as e:
        print(f"Error sending push notification: {e}")
        return False

def send_notification_to_user(conn, user_id, notification_data):
    """
    Send push notification to all subscriptions of a user.
    
    Args:
        conn: Database connection
        user_id: ID of the user to send notification to
        notification_data: Dictionary with notification title, body, etc.
    
    Returns:
        Number of successful sends
    """
    subscriptions = database.get_push_subscriptions(conn, user_id)
    success_count = 0
    
    for sub in subscriptions:
        result = send_push_notification(sub, notification_data)
        if result is True:
            success_count += 1
        elif result == 'gone':
            # Remove invalid subscription
            database.delete_push_subscription(conn, user_id, sub['endpoint'])
    
    return success_count

def send_message_notification(conn, recipient_id, sender_name, message_content, chat_name=None):
    """
    Send a notification for a new message.
    
    Args:
        conn: Database connection
        recipient_id: ID of the user to notify
        sender_name: Name of the sender
        message_content: Content of the message
        chat_name: Name of the chat (for group chats)
    """
    title = chat_name if chat_name else sender_name
    notification_data = {
        "title": f"New message from {title}",
        "body": message_content[:100],  # Limit to 100 chars
        "icon": "/static/icon.png",
        "badge": "/static/badge.png",
        "tag": "message",
        "data": {
            "type": "message",
            "sender": sender_name
        }
    }
    
    return send_notification_to_user(conn, recipient_id, notification_data)

def send_friend_request_notification(conn, recipient_id, requester_name):
    """
    Send a notification for a new friend request.
    
    Args:
        conn: Database connection
        recipient_id: ID of the user to notify
        requester_name: Name of the user who sent the request
    """
    notification_data = {
        "title": "New Friend Request",
        "body": f"{requester_name} sent you a friend request",
        "icon": "/static/icon.png",
        "badge": "/static/badge.png",
        "tag": "friend_request",
        "data": {
            "type": "friend_request",
            "requester": requester_name
        }
    }
    
    return send_notification_to_user(conn, recipient_id, notification_data)

def send_friend_accepted_notification(conn, recipient_id, accepter_name):
    """
    Send a notification when a friend request is accepted.
    
    Args:
        conn: Database connection
        recipient_id: ID of the user to notify
        accepter_name: Name of the user who accepted the request
    """
    notification_data = {
        "title": "Friend Request Accepted",
        "body": f"{accepter_name} accepted your friend request",
        "icon": "/static/icon.png",
        "badge": "/static/badge.png",
        "tag": "friend_accepted",
        "data": {
            "type": "friend_accepted",
            "accepter": accepter_name
        }
    }
    
    return send_notification_to_user(conn, recipient_id, notification_data)
