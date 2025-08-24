def test_send_verification_email_no_email(
    create_client_and_cleanup, fixture_create_user
):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}

    # Try to send verification email without setting email
    response = create_client_and_cleanup.post(
        "/send_verification_email/v0", headers=headers
    )
    assert response.status_code == 400
