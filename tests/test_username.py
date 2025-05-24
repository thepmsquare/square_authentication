from square_authentication.messages import messages


def test_register_username_consecutive_special_chars(create_client_and_cleanup):
    payload = {
        "username": "invalid..name",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_starts_with_number(create_client_and_cleanup):
    payload = {
        "username": "1username",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_ends_with_number(create_client_and_cleanup):
    payload = {
        "username": "username1",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_with_space(create_client_and_cleanup):
    payload = {
        "username": "user name",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400
    assert "username" in response.json()["log"]


def test_username_too_short(create_client_and_cleanup):
    payload = {
        "username": "a",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 400
    assert "username" in response.json()["log"]


def test_username_simple_valid(create_client_and_cleanup):
    payload = {
        "username": "johnsmith",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_with_uppercase(create_client_and_cleanup):
    payload = {
        "username": "User_Name",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_with_digits(create_client_and_cleanup):
    payload = {
        "username": "john123smith",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_with_underscore_hyphen(create_client_and_cleanup):
    payload = {
        "username": "john_smith-doe",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]


def test_username_max_length(create_client_and_cleanup):
    payload = {
        "username": "a1234567890_b-cdefgh",
        "password": "testpass123",
        "app_id": 1,
    }
    response = create_client_and_cleanup.post("/register_username/v0", json=payload)
    assert response.status_code == 201
    assert response.json()["message"] == messages["REGISTRATION_SUCCESSFUL"]
