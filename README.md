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