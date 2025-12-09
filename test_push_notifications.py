import requests
import time
import json

BASE_URL = "http://127.0.0.1:5000"

def test_push_notifications():
    print("Testing Push Notification API...")
    
    # 1. Register and login a test user
    print("STEP: Register and login test user")
    username = f"pushtest_{int(time.time())}"
    email = f"{username}@example.com"
    password = "password123"
    
    res = requests.post(f"{BASE_URL}/api/register", json={
        "username": username,
        "email": email,
        "password": password
    })
    print(f"Register: {res.status_code} {res.text}")
    assert res.status_code == 201, "Failed to register user"
    
    res = requests.post(f"{BASE_URL}/api/login", json={
        "username": username,
        "password": password
    })
    print(f"Login: {res.status_code} {res.text}")
    assert res.status_code == 200, "Failed to login"
    token = res.json()['token']
    
    # 2. Get VAPID public key
    print("\nSTEP: Get VAPID public key")
    res = requests.get(f"{BASE_URL}/api/vapid_public_key")
    print(f"Get VAPID public key: {res.status_code}")
    assert res.status_code == 200, "Failed to get VAPID public key"
    vapid_data = res.json()
    assert 'publicKey' in vapid_data, "VAPID public key not in response"
    print(f"Public key length: {len(vapid_data['publicKey'])}")
    assert len(vapid_data['publicKey']) > 0, "VAPID public key is empty"
    
    # 3. Subscribe to push notifications
    print("\nSTEP: Subscribe to push notifications")
    # Simulate a push subscription
    subscription_data = {
        "token": token,
        "endpoint": "https://fcm.googleapis.com/fcm/send/test-endpoint-123",
        "p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
        "auth": "tBHItJI5svbpez7KI4CCXg"
    }
    
    res = requests.post(f"{BASE_URL}/api/push/subscribe", json=subscription_data)
    print(f"Subscribe to push: {res.status_code} {res.text}")
    assert res.status_code == 200, "Failed to subscribe to push notifications"
    
    # 4. Subscribe again with same endpoint (should update, not error)
    print("\nSTEP: Subscribe again with same endpoint")
    res = requests.post(f"{BASE_URL}/api/push/subscribe", json=subscription_data)
    print(f"Subscribe again: {res.status_code} {res.text}")
    assert res.status_code == 200, "Failed to update subscription"
    
    # 5. Subscribe with different endpoint for same user
    print("\nSTEP: Subscribe with different endpoint")
    subscription_data2 = subscription_data.copy()
    subscription_data2["endpoint"] = "https://fcm.googleapis.com/fcm/send/test-endpoint-456"
    
    res = requests.post(f"{BASE_URL}/api/push/subscribe", json=subscription_data2)
    print(f"Subscribe with different endpoint: {res.status_code} {res.text}")
    assert res.status_code == 200, "Failed to subscribe with different endpoint"
    
    # 6. Test invalid token
    print("\nSTEP: Test subscription with invalid token")
    invalid_sub = subscription_data.copy()
    invalid_sub["token"] = "invalid_token_123"
    
    res = requests.post(f"{BASE_URL}/api/push/subscribe", json=invalid_sub)
    print(f"Subscribe with invalid token: {res.status_code} {res.text}")
    assert res.status_code == 401, "Should reject invalid token"
    
    # 7. Test missing subscription data
    print("\nSTEP: Test subscription with missing data")
    incomplete_sub = {"token": token, "endpoint": "https://test.com"}
    
    res = requests.post(f"{BASE_URL}/api/push/subscribe", json=incomplete_sub)
    print(f"Subscribe with missing data: {res.status_code} {res.text}")
    assert res.status_code == 400, "Should reject incomplete subscription data"
    
    # 8. Unsubscribe from push notifications
    print("\nSTEP: Unsubscribe from push notifications")
    unsubscribe_data = {
        "token": token,
        "endpoint": subscription_data["endpoint"]
    }
    
    res = requests.post(f"{BASE_URL}/api/push/unsubscribe", json=unsubscribe_data)
    print(f"Unsubscribe: {res.status_code} {res.text}")
    assert res.status_code == 200, "Failed to unsubscribe"
    
    # 9. Unsubscribe again (should return 404)
    print("\nSTEP: Unsubscribe again (should fail)")
    res = requests.post(f"{BASE_URL}/api/push/unsubscribe", json=unsubscribe_data)
    print(f"Unsubscribe again: {res.status_code} {res.text}")
    assert res.status_code == 404, "Should return 404 for non-existent subscription"
    
    # 10. Test unsubscribe with invalid token
    print("\nSTEP: Test unsubscribe with invalid token")
    invalid_unsub = unsubscribe_data.copy()
    invalid_unsub["token"] = "invalid_token_123"
    
    res = requests.post(f"{BASE_URL}/api/push/unsubscribe", json=invalid_unsub)
    print(f"Unsubscribe with invalid token: {res.status_code} {res.text}")
    assert res.status_code == 401, "Should reject invalid token"
    
    # 11. Test notification module functions (basic imports)
    print("\nSTEP: Test notification module imports")
    try:
        import sys
        sys.path.insert(0, '/home/runner/work/SimpleChat/SimpleChat')
        from notifications import (
            send_message_notification,
            send_friend_request_notification,
            send_friend_accepted_notification
        )
        print("✓ Notification module functions imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import notification functions: {e}")
        raise
    
    print("\n" + "="*60)
    print("All push notification tests passed!")
    print("="*60)

if __name__ == "__main__":
    test_push_notifications()
