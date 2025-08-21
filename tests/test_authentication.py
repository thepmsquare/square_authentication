from square_authentication.messages import messages


def test_login_google_invalid_token(create_client_and_cleanup):
    payload = {"google_id": "invalid_token", "app_id": 1}
    response = create_client_and_cleanup.post("/register_login_google/v0", json=payload)
    assert response.status_code == 400


def test_register_username_validation(create_client_and_cleanup):
    # Test username too short
    payload = {"username": "a", "password": "testpass123", "app_id": 1}
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


def test_duplicate_username_registration(
    create_client_and_cleanup, fixture_create_user
):
    create_user_input, create_user_output = fixture_create_user

    # Try to register with same username
    payload = {
        "username": create_user_output["data"]["main"]["username"],
        "password": "different_password123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 409
    assert response.json()["message"] == messages["USERNAME_ALREADY_EXISTS"]
