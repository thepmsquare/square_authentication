# square_authentication

## about

authentication layer for my personal server.

## Installation

```shell
pip install square_authentication
```

## env

- python>=3.12.0

## changelog

### v9.0.1

- env
    - add RESEND_COOL_DOWN_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS and
      RESEND_COOL_DOWN_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS in LOGIC section.
- profile
    - add validation for email verification code already sent in send_verification_email_v0.
    - add cooldown_reset_at in send_verification_email_v0 output.
- core
    - add validation for email password reset code already sent in send_reset_password_email_v0.
    - add cooldown_reset_at in send_reset_password_email_v0 output.

### v9.0.0

- core
    - **breaking change**: new mandatory parameter `app_id` in validate_and_get_payload_from_token_v0.

### v8.0.2

- core
    - add refresh_token_expiry_time in output for reset_password_and_login_using_backup_code_v0 and
      reset_password_and_login_using_reset_email_code_v0.

### v8.0.1

- core
    - add make recovery_methods_to_add and recovery_methods_to_remove parameters optional in
      update_user_recovery_methods_v0.

### v8.0.0

- env
    - add GOOGLE section and GOOGLE_AUTH_PLATFORM_CLIENT_ID variable.
    - add LOGIC section with NUMBER_OF_RECOVERY_CODES, EXPIRY_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS,
      NUMBER_OF_DIGITS_IN_EMAIL_VERIFICATION_CODE, EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS,
      NUMBER_OF_DIGITS_IN_EMAIL_PASSWORD_RESET_CODE variables.
- dependencies
    - add google-auth>=2.40.3.
    - update square_commons to >=3.0.0.
- core
    - add reset_password_and_login_using_reset_email_code_v0.
    - **breaking change**: remove app_id from send_reset_password_email_v0.
    - implement deletion of existing backup codes before generating new ones (generate_account_backup_codes_v0).
    - implement deletion of existing backup codes before removing recovery method (update_user_recovery_methods_v0).
    - implement logout_other_sessions in update_password_v0, reset_password_and_login_using_backup_code_v0 and
      reset_password_and_login_using_reset_email_code_v0
        - in update_password_v0, it will log out all other sessions except the current one if valid (optional)
          refresh_token is passed in.
    - add register_login_google_v0, **finally**.
    - add validation in update_password_v0, reset_password_and_login_using_backup_code_v0, send_reset_password_email_v0,
      reset_password_and_login_using_reset_email_code_v0 to check if user has credentials and has self as auth provider.
    - remove profile_photo from file_store when user is deleted in delete_user_v0.
- utils
    - add new core file with generate_default_username_for_google_users function.
- tests
    - add test_login_fail_v0.

### v7.0.0

- internal support for UserAuthProvider.
- internal support for username shifted from UserProfile to User.
- internal support for phone number country code in UserProfile.
- core
    - register_username_v0 fixed to account for changes mentioned above and creates empty profile.
    - login_username_v0 fixed to account for changes mentioned above.
    - update_username_v0 fixed to account for changes mentioned above.
    - **breaking change**: delete_user_v0 is now a POST method instead of DELETE.
    - add generate_account_backup_codes_v0.
    - add reset_password_and_login_using_backup_code_v0.
    - add validation for email verification when adding email as recovery method in update_user_recovery_methods_v0.
    - add send_reset_password_email_v0.
- profile
    - add update_profile_details_v0.
    - add send_verification_email_v0.
    - add validate_email_verification_code_v0.
- tests
    - add test cases and fixtures for login_username_v0.
    - add test cases and fixtures for delete_user_v0.
    - add test cases and fixtures for update_profile_details_v0.
- env
    - add EMAIL section and MAIL_GUN_API_KEY variable.

### v6.2.2

- remove config.ini and config.testing.ini from version control.

### v6.2.1

- core
    - tweak validation for username in register_username_v0 and update_username_v0.

### v6.2.0

- core
    - add update_user_recovery_methods_v0.

### v6.1.0

- add validation to username in register_username_v0 and update_username_v0.
- add test cases for register_username_v0.

### v6.0.5

- env
    - add ALLOW_ORIGINS

### v6.0.4

- mock ini file for pytest.

### v6.0.3

- make profile photo upload optional in update_profile_photo/v0, to enable users to remove their profile photo.

### v6.0.2

- bump square_file_store_helper to >=3.0.0.
- use upload_file_using_tuple_v0 instead of upload_file_using_path_v0 in update_profile_photo/v0.

### v6.0.1

- delete previous profile photo from file store after successfully updating profile photo.

### v6.0.0

- add profile details in get_user_details_v0 instead of credentials keyword.

### v5.2.0

- add temp folder to .gitignore.
- add square_file_store_helper as a dependency.
- config
    - add config section for file store helper.
- initialise file store helper and database helper in config.py
- add profile router
- profile
    - add update_profile_photo/v0
- update messages.

### v5.1.5

- bump square_logger to >=2.0.0.

### v5.1.4

- re bug fix v5.1.3

### v5.1.3

- bugfix in login_username/v0 (getting creds from correct table).

### v5.1.2

- bump square_database_structure>=2.3.1.
- change logic to read username from profile instead of credentials table.

### v5.1.1

- add logger decorator in all functions.
- add error logs in all endpoints.

### v5.1.0

- Core
    - add logout/apps/v0.
    - add logout/all/v0.

### v5.0.1

- fix typo in return value of get_user_details_v0.

### v5.0.0

- change get_user_details_v0 to return app name instead of app ids.

### v4.5.1

- fix auto docker image build github action.

### v4.5.0

- add pytest dependency and dummy test.
- add https dependency.
- github actions for CI/CD for testing and auto build and push.

### v4.4.0

- core
    - add refresh_token_expiry_time in register_username_v0, login_username_v0.

### v4.3.0

- set allow_credentials=True.

### v4.2.1

- fix output format in validate_and_get_payload_from_token/v0.
- add db check refresh token validation in validate_and_get_payload_from_token/v0.

### v4.2.0

- add validate_and_get_payload_from_token/v0 in core.

### v4.1.0

- add get_text_hash/v0 in utils.

### v4.0.1

- bugfix in pydantic model import.

### v4.0.0

- /login_username/v0 is now POST method.
- new flag in /login_username/v0 assign_app_id_if_missing.
- bugfix: /get_user_details/v0 now only returns number of active sessions.

### v3.0.0

- added new endpoints
    - /update_username/v0
    - /delete_user/v0
    - /update_password/v0
- move data in password related endpoints to request body from params.
- /register_username/v0 now takes in app_id as optional parameter to assign user to that app and create session for it.
- /generate_access_token/v0 now only needs refresh token (removed validation).
- /logout/v0 now only needs refresh token (removed validation).
- /update_user_app_ids/v0 now only updates ids for self (user). added access token as input param and removed user_id.
- /get_user_app_ids/v0 is now /get_user_details/v0 with access token as the only input param.

### v2.0.0

- authentication module needs to be used across applications so
    - register_username: will not create sessions and therefore will not auto login.
    - login: added validation if app is assigned to user before assigning it and added app_id in session row.
    - logout: added app_id as new parameter and validation for that.
    - generate_access_token: added app_id as new parameter and validation for that.
- added 2 new endpoints
    - get user app ids: **access token validation pending**.
    - change user app ids: **access token validation pending**.
- add versions for all endpoint paths.
- make it compatible with square_database_helper 2.x.
- username in database will always be lowercase.
- standardise output formats for all api.

### v1.0.0

- initial implementation.

## Feedback is appreciated. Thank you!
