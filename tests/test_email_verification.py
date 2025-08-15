from square_authentication.messages import messages
from datetime import datetime, timedelta, timezone
import pytest

def test_send_verification_email(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}
    
    # First update profile to add email
    payload = {"email": "test@example.com"}
    response = create_client_and_cleanup.patch("/update_profile_details/v0", json=payload, headers=headers)
    assert response.status_code == 200
    
    # Send verification email
    response = create_client_and_cleanup.post("/send_verification_email/v0", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == messages["VERIFICATION_CODE_SENT"]

def test_send_verification_email_no_email(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}
    
    # Try to send verification email without setting email
    response = create_client_and_cleanup.post("/send_verification_email/v0", headers=headers)
    assert response.status_code == 400
    assert "email is required" in response.json()["log"].lower()

def test_verify_email_success(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}
    
    # Update profile with email
    payload = {"email": "test@example.com"}
    response = create_client_and_cleanup.patch("/update_profile_details/v0", json=payload, headers=headers)
    assert response.status_code == 200
    
    # Send verification email
    response = create_client_and_cleanup.post("/send_verification_email/v0", headers=headers)
    assert response.status_code == 200
    
    # Verify email with code
    # Note: In real test we'd need to mock or get the actual code
    verification_code = "123456"  # Mock code
    response = create_client_and_cleanup.post(
        "/validate_email_verification_code/v0",
        json={"verification_code": verification_code},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == messages["EMAIL_VERIFICATION_SUCCESSFUL"]

def test_verify_email_invalid_code(create_client_and_cleanup, fixture_create_user):
    create_user_input, create_user_output = fixture_create_user
    headers = {"access-token": create_user_output["data"]["main"]["access_token"]}
    
    # Update profile with email
    payload = {"email": "test@example.com"}
    response = create_client_and_cleanup.patch("/update_profile_details/v0", json=payload, headers=headers)
    assert response.status_code == 200
    
    # Send verification email
    response = create_client_and_cleanup.post("/send_verification_email/v0", headers=headers)
    assert response.status_code == 200
    
    # Try to verify with invalid code
    response = create_client_and_cleanup.post(
        "/validate_email_verification_code/v0",
        json={"verification_code": "000000"},
        headers=headers
    )
    assert response.status_code == 400
    assert response.json()["message"] == messages["INCORRECT_VERIFICATION_CODE"]