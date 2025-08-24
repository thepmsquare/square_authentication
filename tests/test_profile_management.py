from square_authentication.messages import messages


def test_update_profile_details_full(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    payload = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number_country_code": "+1",
        "phone_number": "1234567890",
    }

    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", params=payload, headers=headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == messages["GENERIC_UPDATE_SUCCESSFUL"]


def test_update_profile_details_partial(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    # Update only first name
    payload = {"first_name": "John"}
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", params=payload, headers=headers
    )
    assert response.status_code == 200

    # Update only last name
    payload = {"last_name": "Doe"}
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", params=payload, headers=headers
    )
    assert response.status_code == 200


def test_update_profile_invalid_email(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    payload = {"email": "invalid-email"}
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", params=payload, headers=headers
    )
    assert response.status_code == 400
    assert response.json()["message"] == messages["INVALID_EMAIL_FORMAT"]


def test_update_profile_invalid_phone(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    # Phone number without country code
    payload = {"phone_number": "1234567890"}
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0",
        params=payload,
        headers=headers,
    )
    assert response.status_code == 400

    # Invalid phone number (non-numeric)
    payload = {"phone_number": "abc123", "phone_number_country_code": "+1"}
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", params=payload, headers=headers
    )
    assert response.status_code == 400
    assert response.json()["message"] == messages["INVALID_PHONE_NUMBER_FORMAT"]


def test_get_user_details(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    # First update some profile details
    update_payload = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
    }
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", params=update_payload, headers=headers
    )
    assert response.status_code == 200

    # Get user details
    response = create_client_and_cleanup.get("/get_user_details/v0", headers=headers)
    assert response.status_code == 200
    data = response.json()["data"]["main"]

    # Verify profile information
    assert data["profile"]["user_profile_first_name"] == "John"
    assert data["profile"]["user_profile_last_name"] == "Doe"
    assert data["profile"]["user_profile_email"] == "john.doe@example.com"
