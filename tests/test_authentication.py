from square_authentication.messages import messages
from datetime import datetime, timedelta

def test_login_google_v0(create_client_and_cleanup, fixture_google_token):
    google_token, user_info = fixture_google_token
    payload = {
        "google_token": google_token,
        "app_id": 1
    }
    response = create_client_and_cleanup.post("/register_login_google/v0", json=payload)
    assert response.status_code == 200
    assert "access_token" in response.json()["data"]["main"]
    assert "refresh_token" in response.json()["data"]["main"]

def test_login_google_invalid_token(create_client_and_cleanup):
    payload = {
        "google_token": "invalid_token",
        "app_id": 1
    }
    response = create_client_and_cleanup.post("/register_login_google/v0", json=payload)
    assert response.status_code == 400
    assert "invalid token" in response.json()["log"].lower()

def test_login_username_rate_limit(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    payload = {
        "username": create_user_output["data"]["main"]["username"],
        "password": "wrong_password",
        "app_id": create_user_input["app_id"]
    }
    
    # Make multiple failed login attempts
    for _ in range(5):
        response = create_client_and_cleanup.post("/login_username/v0", json=payload)
        assert response.status_code == 400
    
    # Try with correct password (should still fail due to rate limit)
    payload["password"] = create_user_input["password"]
    response = create_client_and_cleanup.post("/login_username/v0", json=payload)
    assert response.status_code == 429
    assert "too many attempts" in response.json()["log"].lower()

def test_register_username_validation(create_client_and_cleanup):
    # Test username too short
    payload = {
        "username": "a",
        "password": "testpass123",
        "app_id": 1
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400
    
    # Test username too long
    payload["username"] = "a" * 31
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400
    
    # Test username with invalid characters
    payload["username"] = "user@name"
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400

def test_password_validation(create_client_and_cleanup):
    # Test password too short
    payload = {
        "username": "validuser",
        "password": "short",
        "app_id": 1
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400
    
    # Test password without numbers
    payload["password"] = "noNumbersHere"
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400
    
    # Test password without letters
    payload["password"] = "12345678"
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400

def test_duplicate_username_registration(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    
    # Try to register with same username
    payload = {
        "username": create_user_output["data"]["main"]["username"],
        "password": "different_password123",
        "app_id": 1
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 409
    assert response.json()["message"] == messages["USERNAME_ALREADY_EXISTS"]