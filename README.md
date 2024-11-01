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
    - change logic of register username: will not create sessions and therefore will not auto login.
    - login: tbd
    - logout: tbd
    - generate_access_token: tbd
- added 2 new endpoints
    - get user app ids: access token validation pending
    - change user app ids: access token validation pending
- add versions for all endpoint paths
- make it compatible with square_database_helper 2.x
- username in database will always be lowercase
- standardise output formats for all api

### v1.0.0

- initial implementation.

## Feedback is appreciated. Thank you!