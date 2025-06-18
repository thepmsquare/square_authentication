from square_authentication.messages import messages


def test_update_profile_details_v0(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}
    payload = {
        "email": "dummy@email.com",
    }
    response = create_client_and_cleanup.patch(
        "/update_profile_details/v0", json=payload, headers=headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == messages["GENERIC_UPDATE_SUCCESSFUL"]
