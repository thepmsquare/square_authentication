from square_authentication.messages import messages


def test_login_v0(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    payload = {
        "username": create_user_output["data"]["main"]["username"],
        "password": create_user_input["password"],
        "app_id": create_user_input["app_id"],
    }
    response = create_client_and_cleanup.post("/login_username/v0", json=payload)
    assert response.status_code == 200
    assert response.json()["message"] == messages["LOGIN_SUCCESSFUL"]


def test_login_fail_v0(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    payload = {
        "username": create_user_output["data"]["main"]["username"],
        "password": create_user_input["password"] + "233",
        "app_id": create_user_input["app_id"],
    }
    response = create_client_and_cleanup.post("/login_username/v0", json=payload)
    assert response.status_code == 400
    assert response.json()["message"] == messages["INCORRECT_PASSWORD"]
