from square_authentication.messages import messages


def test_generate_access_token(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"refresh-token": create_user_output["data"]["main"]["refresh_token"]}

    response = create_client_and_cleanup.get(
        "/generate_access_token/v0", headers=headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == messages["GENERIC_CREATION_SUCCESSFUL"]
    assert "access_token" in response.json()["data"]["main"]


def test_generate_access_token_invalid_refresh_token(create_client_and_cleanup):
    headers = {"refresh-token": "invalid_token"}
    response = create_client_and_cleanup.get(
        "/generate_access_token/v0", headers=headers
    )
    assert response.status_code == 400
    assert response.json()["message"] == messages["INCORRECT_REFRESH_TOKEN"]


def test_logout_specific_app(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    payload = {"app_ids": [create_user_input["app_id"]]}
    response = create_client_and_cleanup.post(
        "/logout/apps/v0", json=payload, headers=headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == messages["LOGOUT_SUCCESSFUL"]


def test_logout_all_sessions(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    response = create_client_and_cleanup.delete("/logout/all/v0", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == messages["LOGOUT_SUCCESSFUL"]

    # Try to use the same refresh token (should fail)
    response = create_client_and_cleanup.get(
        "/generate_access_token/v0",
        headers={"refresh-token": create_user_output["data"]["main"]["refresh_token"]},
    )
    assert response.status_code == 400
    assert response.json()["message"] == messages["INCORRECT_REFRESH_TOKEN"]


def test_logout_single_session(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"refresh-token": create_user_output["data"]["main"]["refresh_token"]}

    response = create_client_and_cleanup.delete("/logout/v0", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == messages["LOGOUT_SUCCESSFUL"]

    # Try to use the same refresh token (should fail)
    response = create_client_and_cleanup.get(
        "/generate_access_token/v0", headers=headers
    )
    assert response.status_code == 400
    assert response.json()["message"] == messages["INCORRECT_REFRESH_TOKEN"]
