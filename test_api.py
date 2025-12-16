import requests
import time

BASE_URL = "http://127.0.0.1:5000"

def test_api():
    print("Testing API...")
    
    # 1. Register User 1
    print("STEP: Register User 1")
    username1 = f"user1_{int(time.time())}"
    email1 = f"{username1}@example.com"
    password = "password123"
    
    res = requests.post(f"{BASE_URL}/api/register", json={
        "username": username1,
        "email": email1,
        "password": password
    })
    print(f"Register User 1: {res.status_code} {res.text}")
    assert res.status_code == 201
    
    # 2. Login User 1
    print("STEP: Login User 1")
    res = requests.post(f"{BASE_URL}/api/login", json={
        "username": username1,
        "password": password
    })
    print(f"Login User 1: {res.status_code} {res.text}")
    assert res.status_code == 200
    token1 = res.json()['token']
    
    # 3. Get User Me
    print("STEP: Get User Me")
    res = requests.post(f"{BASE_URL}/api/user/me", json={"token": token1})
    print(f"Get User Me: {res.status_code} {res.text}")
    assert res.status_code == 200
    user1_id = res.json()['user']['id']
    
    # 4. Register User 2
    print("STEP: Register User 2")
    username2 = f"user2_{int(time.time())}"
    email2 = f"{username2}@example.com"
    
    res = requests.post(f"{BASE_URL}/api/register", json={
        "username": username2,
        "email": email2,
        "password": password
    })
    print(f"Register User 2: {res.status_code} {res.text}")
    assert res.status_code == 201
    
    # 5. Login User 2
    print("STEP: Login User 2")
    res = requests.post(f"{BASE_URL}/api/login", json={
        "username": username2,
        "password": password
    })
    print(f"Login User 2: {res.status_code} {res.text}")
    assert res.status_code == 200
    token2 = res.json()['token']
    
    # 6. Friend Request (User 1 -> User 2)
    print("STEP: Friend Request (User 1 -> User 2)")
    # Get User 2 ID
    res = requests.post(f"{BASE_URL}/api/user/me", json={"token": token2})
    user2_id = res.json()['user']['id']
    
    res = requests.post(f"{BASE_URL}/api/friend_request", json={
        "token": token1,
        "friend_id": user2_id
    })
    print(f"Friend Request: {res.status_code} {res.text}")
    assert res.status_code == 200
    
    # 7. Accept Friend Request (User 2 -> User 1)
    print("STEP: Accept Friend Request (User 2 -> User 1)")
    res = requests.post(f"{BASE_URL}/api/friend_request", json={
        "token": token2,
        "friend_id": user1_id
    })
    print(f"Accept Friend Request: {res.status_code} {res.text}")
    assert res.status_code == 200
    
    # 8. Get Friends (User 1)
    print("STEP: Get Friends (User 1)")
    res = requests.post(f"{BASE_URL}/api/friends", json={"token": token1})
    print(f"Get Friends User 1: {res.status_code} {res.text}")
    assert res.status_code == 200
    assert len(res.json()['friends']) > 0
    
    # 9. Create Group
    print("STEP: Create Group")
    group_name = f"Group_{int(time.time())}"
    res = requests.post(f"{BASE_URL}/api/groups", json={
        "token": token1,
        "name": group_name,
        "description": "Test Group"
    })
    print(f"Create Group: {res.status_code} {res.text}")
    assert res.status_code == 201
    group_id = res.json()['group_id']

    # 10. Add User 2 to Group
    print("STEP: Add User 2 to Group")
    res = requests.post(f"{BASE_URL}/api/groups/{group_id}/members", json={
        "token": token1,
        "user_id": user2_id
    })
    print(f"Add User 2 to Group: {res.status_code} {res.text}")
    assert res.status_code == 200

    # 11. Send Group Message (User 1)
    print("STEP: Send Group Message (User 1)")
    res = requests.post(f"{BASE_URL}/api/message/send", json={
        "token": token1,
        "chat_id": group_id,
        "content": "Hello Group!",
        "is_group": True
    })
    print(f"Send Group Message: {res.status_code} {res.text}")
    assert res.status_code == 200

    # 12. Get Group Messages (User 2)
    print("STEP: Get Group Messages (User 2)")
    res = requests.post(f"{BASE_URL}/api/messages", json={
        "token": token2,
        "chat_id": group_id,
        "is_group": True
    })
    print(f"Get Group Messages: {res.status_code} {res.text}")
    assert res.status_code == 200
    assert len(res.json()['messages']) > 0
    assert res.json()['messages'][0]['content'] == "Hello Group!" # content check

    # 13. Leave Group (User 2)
    print("STEP: Leave Group (User 2)")
    res = requests.post(f"{BASE_URL}/api/groups/{group_id}/leave", json={
        "token": token2
    })
    print(f"Leave Group: {res.status_code} {res.text}")
    assert res.status_code == 200

    # 14. Delete Group (User 1)
    print("STEP: Delete Group (User 1)")
    res = requests.delete(f"{BASE_URL}/api/groups/{group_id}", params={"token": token1})
    print(f"Delete Group: {res.status_code} {res.text}")
    assert res.status_code == 200

    # 15. Delete Friend (User 1 -> User 2)
    print("STEP: Delete Friend (User 1 -> User 2)")
    res = requests.delete(f"{BASE_URL}/api/friends/{user2_id}", params={"token": token1})
    print(f"Delete Friend: {res.status_code} {res.text}")
    assert res.status_code == 200

    print("All tests passed!")

if __name__ == "__main__":
    test_api()
