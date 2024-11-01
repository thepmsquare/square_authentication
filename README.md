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