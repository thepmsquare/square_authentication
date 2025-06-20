import copy
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, List

import bcrypt
import jwt
from fastapi import APIRouter, Header, HTTPException, status
from fastapi.params import Query
from fastapi.responses import JSONResponse
from requests import HTTPError
from square_commons import get_api_output_in_standard_format
from square_database_helper.pydantic_models import FilterConditionsV0, FiltersV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.enums import (
    RecoveryMethodEnum,
    AuthProviderEnum,
    VerificationCodeTypeEnum,
)
from square_database_structure.square.authentication.tables import (
    User,
    UserApp,
    UserCredential,
    UserSession,
    UserProfile,
    UserRecoveryMethod,
    UserAuthProvider,
    UserVerificationCode,
)
from square_database_structure.square.public import (
    global_string_schema_name as global_string_public_schema_name,
)
from square_database_structure.square.public.tables import App

from square_authentication.configuration import (
    config_int_access_token_valid_minutes,
    config_int_refresh_token_valid_minutes,
    config_str_secret_key_for_access_token,
    config_str_secret_key_for_refresh_token,
    global_object_square_logger,
    global_object_square_database_helper,
)
from square_authentication.messages import messages
from square_authentication.pydantic_models.core import (
    DeleteUserV0,
    LoginUsernameV0,
    LogoutAppsV0,
    RegisterUsernameV0,
    TokenType,
    UpdatePasswordV0,
    ResetPasswordAndLoginUsingBackupCodeV0,
)
from square_authentication.utils.token import get_jwt_payload

router = APIRouter(
    tags=["core"],
)


@router.post("/register_username/v0")
@global_object_square_logger.auto_logger()
async def register_username_v0(
    body: RegisterUsernameV0,
):
    username = body.username
    password = body.password
    app_id = body.app_id

    local_str_user_id = None
    local_str_access_token = None
    local_str_refresh_token = None
    local_object_refresh_token_expiry_time = None
    username = username.lower()
    try:
        """
        validation
        """
        # validation for username
        username_pattern = re.compile(r"^[a-z0-9._-]{2,20}$")
        if not username_pattern.match(username):
            output_content = get_api_output_in_standard_format(
                message=messages["USERNAME_INVALID"],
                log=f"username '{username}' is invalid. it must start and end with a letter, "
                f"contain only lowercase letters, numbers, underscores, or hyphens, "
                f"and not have consecutive separators.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        local_list_response_user_creds = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters=FiltersV0(
                    root={User.user_username.name: FilterConditionsV0(eq=username)}
                ),
            )["data"]["main"]
        )
        if len(local_list_response_user_creds) > 0:
            output_content = get_api_output_in_standard_format(
                message=messages["USERNAME_ALREADY_EXISTS"],
                log=f"an account with the username {username} already exists.",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=output_content,
            )

        """
        main process
        """
        # entry in user table
        local_list_response_user = global_object_square_database_helper.insert_rows_v0(
            data=[
                {
                    User.user_username.name: username,
                }
            ],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
        )["data"]["main"]
        local_str_user_id = local_list_response_user[0][User.user_id.name]

        # entry in user auth provider table
        local_list_response_user_auth_provider = global_object_square_database_helper.insert_rows_v0(
            data=[
                {
                    UserAuthProvider.user_id.name: local_str_user_id,
                    UserAuthProvider.auth_provider.name: AuthProviderEnum.SELF.value,
                }
            ],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserAuthProvider.__tablename__,
        )[
            "data"
        ][
            "main"
        ]
        local_str_user_id = local_list_response_user[0][User.user_id.name]

        # entry in user profile table
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            data=[
                {
                    UserProfile.user_id.name: local_str_user_id,
                }
            ],
        )

        # entry in credential table

        # hash password
        local_str_hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        global_object_square_database_helper.insert_rows_v0(
            data=[
                {
                    UserCredential.user_id.name: local_str_user_id,
                    UserCredential.user_credential_hashed_password.name: local_str_hashed_password,
                }
            ],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
        )
        if app_id is not None:
            # assign app to user
            global_object_square_database_helper.insert_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserApp.__tablename__,
                data=[
                    {
                        UserApp.user_id.name: local_str_user_id,
                        UserApp.app_id.name: app_id,
                    }
                ],
            )

            # return new access token and refresh token
            # create access token
            local_dict_access_token_payload = {
                "app_id": app_id,
                "user_id": local_str_user_id,
                "exp": datetime.now(timezone.utc)
                + timedelta(minutes=config_int_access_token_valid_minutes),
            }
            local_str_access_token = jwt.encode(
                local_dict_access_token_payload,
                config_str_secret_key_for_access_token,
            )

            # create refresh token
            local_object_refresh_token_expiry_time = datetime.now(
                timezone.utc
            ) + timedelta(minutes=config_int_refresh_token_valid_minutes)

            local_dict_refresh_token_payload = {
                "app_id": app_id,
                "user_id": local_str_user_id,
                "exp": local_object_refresh_token_expiry_time,
            }
            local_str_refresh_token = jwt.encode(
                local_dict_refresh_token_payload,
                config_str_secret_key_for_refresh_token,
            )
            # entry in user session table
            global_object_square_database_helper.insert_rows_v0(
                data=[
                    {
                        UserSession.user_id.name: local_str_user_id,
                        UserSession.app_id.name: app_id,
                        UserSession.user_session_refresh_token.name: local_str_refresh_token,
                        UserSession.user_session_expiry_time.name: local_object_refresh_token_expiry_time.strftime(
                            "%Y-%m-%d %H:%M:%S.%f+00"
                        ),
                    }
                ],
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserSession.__tablename__,
            )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["REGISTRATION_SUCCESSFUL"],
            data={
                "main": {
                    "user_id": local_str_user_id,
                    "username": username,
                    "app_id": app_id,
                    "access_token": local_str_access_token,
                    "refresh_token": local_str_refresh_token,
                    "refresh_token_expiry_time": local_object_refresh_token_expiry_time.isoformat(),
                },
            },
        )
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        """
        rollback logic
        """
        if local_str_user_id:
            global_object_square_database_helper.delete_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters=FiltersV0(
                    root={User.user_id.name: FilterConditionsV0(eq=local_str_user_id)}
                ),
            )
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.get("/get_user_details/v0")
@global_object_square_logger.auto_logger()
async def get_user_details_v0(
    access_token: Annotated[str, Header()],
):
    try:
        """
        validation
        """
        # validate access token
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]
        """
        main process
        """
        local_list_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_public_schema_name,
            table_name=App.__tablename__,
            apply_filters=False,
            filters=FiltersV0(root={}),
        )["data"]["main"]
        local_list_response_user_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={UserApp.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
        )["data"]["main"]
        local_list_response_user_profile = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserProfile.__tablename__,
                filters=FiltersV0(
                    root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
                ),
            )["data"]["main"]
        )
        local_list_response_user_sessions = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserSession.__tablename__,
                filters=FiltersV0(
                    root={
                        UserSession.user_id.name: FilterConditionsV0(eq=user_id),
                        UserSession.user_session_expiry_time.name: FilterConditionsV0(
                            gte=datetime.now(timezone.utc).isoformat()
                        ),
                    }
                ),
            )["data"]["main"]
        )
        user_profile = copy.deepcopy(local_list_response_user_profile[0])
        del user_profile[UserProfile.user_id.name]
        """
        return value
        """
        return_this = {
            "user_id": user_id,
            "profile": user_profile,
            "apps": [
                y[App.app_name.name]
                for y in local_list_app
                if y[App.app_id.name]
                in [x[UserApp.app_id.name] for x in local_list_response_user_app]
            ],
            "sessions": [
                {
                    "app_name": [
                        y[App.app_name.name]
                        for y in local_list_app
                        if y[App.app_id.name] == x[UserApp.app_id.name]
                    ][0],
                    "active_sessions": len(
                        [
                            y
                            for y in local_list_response_user_sessions
                            if y[UserSession.app_id.name] == x[UserApp.app_id.name]
                        ]
                    ),
                }
                for x in local_list_response_user_app
            ],
        }
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_READ_SUCCESSFUL"],
            data={"main": return_this},
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=output_content,
        )


@router.patch("/update_user_app_ids/v0")
@global_object_square_logger.auto_logger()
async def update_user_app_ids_v0(
    access_token: Annotated[str, Header()],
    app_ids_to_add: List[int],
    app_ids_to_remove: List[int],
):
    try:

        """
        validation
        """
        # validate access token
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

        app_ids_to_add = list(set(app_ids_to_add))
        app_ids_to_remove = list(set(app_ids_to_remove))

        # check if app_ids_to_add and app_ids_to_remove don't have common ids.
        local_list_common_app_ids = set(app_ids_to_add) & set(app_ids_to_remove)
        if len(local_list_common_app_ids) > 0:
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_400"],
                log=f"invalid app_ids: {list(local_list_common_app_ids)}, present in both add list and remove list.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # check if all app_ids are valid
        local_list_all_app_ids = [*app_ids_to_add, *app_ids_to_remove]
        local_list_response_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_public_schema_name,
            table_name=App.__tablename__,
            apply_filters=False,
            filters=FiltersV0(root={}),
        )["data"]["main"]
        local_list_invalid_ids = [
            x
            for x in local_list_all_app_ids
            if x not in [y[App.app_id.name] for y in local_list_response_app]
        ]
        if len(local_list_invalid_ids) > 0:
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_400"],
                log=f"invalid app_ids: {local_list_invalid_ids}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # logic for adding new app_ids
        local_list_response_user_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={UserApp.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
        )["data"]["main"]
        local_list_new_app_ids = [
            {
                UserApp.user_id.name: user_id,
                UserApp.app_id.name: x,
            }
            for x in app_ids_to_add
            if x not in [y[UserApp.app_id.name] for y in local_list_response_user_app]
        ]
        if len(local_list_new_app_ids) > 0:
            global_object_square_database_helper.insert_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserApp.__tablename__,
                data=local_list_new_app_ids,
            )

        # logic for removing app_ids
        for app_id in app_ids_to_remove:
            global_object_square_database_helper.delete_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserApp.__tablename__,
                filters=FiltersV0(
                    root={
                        UserApp.user_id.name: FilterConditionsV0(eq=user_id),
                        UserApp.app_id.name: FilterConditionsV0(eq=app_id),
                    }
                ),
            )
            # logout user from removed apps
            global_object_square_database_helper.delete_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserSession.__tablename__,
                filters=FiltersV0(
                    root={
                        UserSession.user_id.name: FilterConditionsV0(eq=user_id),
                        UserSession.app_id.name: FilterConditionsV0(eq=app_id),
                    }
                ),
            )

        """
        return value
        """
        # get latest app ids
        local_list_response_user_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={UserApp.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
        )["data"]["main"]
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_UPDATE_SUCCESSFUL"],
            data={
                "main": [x[UserApp.app_id.name] for x in local_list_response_user_app]
            },
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=output_content,
        )


@router.post("/login_username/v0")
@global_object_square_logger.auto_logger()
async def login_username_v0(body: LoginUsernameV0):
    username = body.username
    password = body.password
    app_id = body.app_id
    assign_app_id_if_missing = body.assign_app_id_if_missing
    username = username.lower()
    try:
        """
        validation
        """
        # validation for username
        # check if user with username exists
        local_list_response_user = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(
                root={User.user_username.name: FilterConditionsV0(eq=username)}
            ),
        )["data"]["main"]
        if len(local_list_response_user) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USERNAME"],
                log=f"incorrect username {username}",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if user has auth provider as SELF
        local_list_user_auth_provider_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserAuthProvider.__tablename__,
                filters=FiltersV0(
                    root={
                        UserAuthProvider.user_id.name: FilterConditionsV0(
                            eq=local_list_response_user[0][User.user_id.name]
                        ),
                        UserAuthProvider.auth_provider.name: FilterConditionsV0(
                            eq=AuthProviderEnum.SELF.value
                        ),
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_user_auth_provider_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_AUTH_PROVIDER"],
                log=f"{username} not linked with {AuthProviderEnum.SELF.value} auth provider.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if user has credentials (might not be set in case of errors in registration.)
        local_list_authentication_user_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserCredential.__tablename__,
                filters=FiltersV0(
                    root={
                        UserCredential.user_id.name: FilterConditionsV0(
                            eq=local_list_response_user[0][User.user_id.name]
                        )
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_authentication_user_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USERNAME"],
                log=f"incorrect username {username}",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # validate if app_id is assigned to user
        # this will also validate if app_id is valid
        local_dict_user = local_list_authentication_user_response[0]
        local_str_user_id = local_dict_user[UserCredential.user_id.name]
        local_list_user_app_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={
                    UserApp.user_id.name: FilterConditionsV0(eq=local_str_user_id),
                    UserApp.app_id.name: FilterConditionsV0(eq=app_id),
                }
            ),
        )["data"]["main"]
        if len(local_list_user_app_response) == 0:
            if assign_app_id_if_missing:
                try:
                    global_object_square_database_helper.insert_rows_v0(
                        database_name=global_string_database_name,
                        schema_name=global_string_schema_name,
                        table_name=UserApp.__tablename__,
                        data=[
                            {
                                UserApp.user_id.name: local_str_user_id,
                                UserApp.app_id.name: app_id,
                            }
                        ],
                    )
                except HTTPError as he:
                    output_content = get_api_output_in_standard_format(
                        message=messages["GENERIC_400"],
                        log=str(he),
                    )
                    raise HTTPException(
                        status_code=he.response.status_code, detail=output_content
                    )
            else:
                output_content = get_api_output_in_standard_format(
                    message=messages["GENERIC_400"],
                    log=f"user_id {local_str_user_id}({username}) not assigned to app {app_id}.",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=output_content,
                )

        # validate password
        if not (
            bcrypt.checkpw(
                password.encode("utf-8"),
                local_dict_user[
                    UserCredential.user_credential_hashed_password.name
                ].encode("utf-8"),
            )
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_PASSWORD"],
                log=f"incorrect password for user_id {local_str_user_id}({username}).",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # return new access token and refresh token

        # create access token
        local_dict_access_token_payload = {
            "app_id": app_id,
            "user_id": local_str_user_id,
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=config_int_access_token_valid_minutes),
        }
        local_str_access_token = jwt.encode(
            local_dict_access_token_payload,
            config_str_secret_key_for_access_token,
        )

        # create refresh token
        local_object_refresh_token_expiry_time = datetime.now(timezone.utc) + timedelta(
            minutes=config_int_refresh_token_valid_minutes
        )

        local_dict_refresh_token_payload = {
            "app_id": app_id,
            "user_id": local_str_user_id,
            "exp": local_object_refresh_token_expiry_time,
        }
        local_str_refresh_token = jwt.encode(
            local_dict_refresh_token_payload,
            config_str_secret_key_for_refresh_token,
        )
        # entry in user session table
        global_object_square_database_helper.insert_rows_v0(
            data=[
                {
                    UserSession.user_id.name: local_str_user_id,
                    UserSession.app_id.name: app_id,
                    UserSession.user_session_refresh_token.name: local_str_refresh_token,
                    UserSession.user_session_expiry_time.name: local_object_refresh_token_expiry_time.strftime(
                        "%Y-%m-%d %H:%M:%S.%f+00"
                    ),
                }
            ],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserSession.__tablename__,
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            data={
                "main": {
                    "user_id": local_str_user_id,
                    "access_token": local_str_access_token,
                    "refresh_token": local_str_refresh_token,
                    "refresh_token_expiry_time": local_object_refresh_token_expiry_time.isoformat(),
                }
            },
            message=messages["LOGIN_SUCCESSFUL"],
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.get("/generate_access_token/v0")
@global_object_square_logger.auto_logger()
async def generate_access_token_v0(
    refresh_token: Annotated[str, Header()],
):
    try:
        """
        validation
        """
        # validate refresh token
        # validating if a session refresh token exists in the database.
        local_list_user_session_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserSession.__tablename__,
                filters=FiltersV0(
                    root={
                        UserSession.user_session_refresh_token.name: FilterConditionsV0(
                            eq=refresh_token
                        ),
                    }
                ),
            )["data"]["main"]
        )

        if len(local_list_user_session_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_REFRESH_TOKEN"],
                log=f"incorrect refresh token: {refresh_token}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # validating if the refresh token is valid, active and of the same user.
        try:
            local_dict_refresh_token_payload = get_jwt_payload(
                refresh_token, config_str_secret_key_for_refresh_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_REFRESH_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # create and send access token
        local_dict_access_token_payload = {
            "app_id": local_dict_refresh_token_payload["app_id"],
            "user_id": local_dict_refresh_token_payload["user_id"],
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=config_int_access_token_valid_minutes),
        }
        local_str_access_token = jwt.encode(
            local_dict_access_token_payload, config_str_secret_key_for_access_token
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            data={"main": {"access_token": local_str_access_token}},
            message=messages["GENERIC_CREATION_SUCCESSFUL"],
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.delete("/logout/v0")
@global_object_square_logger.auto_logger()
async def logout_v0(
    refresh_token: Annotated[str, Header()],
):
    try:
        """
        validation
        """
        # validate refresh token
        # validating if a session refresh token exists in the database.
        local_list_user_session_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserSession.__tablename__,
                filters=FiltersV0(
                    root={
                        UserSession.user_session_refresh_token.name: FilterConditionsV0(
                            eq=refresh_token
                        ),
                    }
                ),
            )["data"]["main"]
        )

        if len(local_list_user_session_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_REFRESH_TOKEN"],
                log=f"incorrect refresh token: {refresh_token}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # validating if the refresh token is valid, active and of the same user.
        try:
            _ = get_jwt_payload(refresh_token, config_str_secret_key_for_refresh_token)
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_REFRESH_TOKEN"],
                log=str(error),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # ======================================================================================
        # NOTE: if refresh token has expired no need to delete it during this call
        # ======================================================================================
        """
        main process
        """
        # delete session for user
        global_object_square_database_helper.delete_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserSession.__tablename__,
            filters=FiltersV0(
                root={
                    UserSession.user_session_refresh_token.name: FilterConditionsV0(
                        eq=refresh_token
                    ),
                }
            ),
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["LOGOUT_SUCCESSFUL"],
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.delete("/logout/apps/v0")
@global_object_square_logger.auto_logger()
async def logout_apps_v0(
    access_token: Annotated[str, Header()],
    body: LogoutAppsV0,
):
    app_ids = body.app_ids
    try:
        """
        validation
        """
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]
        # validate app_ids
        app_ids = list(set(app_ids))
        local_list_response_user_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={
                    UserApp.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
            columns=[UserApp.app_id.name],
        )["data"]["main"]
        local_list_user_app_ids = [
            x[UserApp.app_id.name] for x in local_list_response_user_app
        ]
        local_list_invalid_app_ids = [
            x for x in app_ids if x not in local_list_user_app_ids
        ]
        if len(local_list_invalid_app_ids) > 0:
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_400"],
                log=f"invalid app_ids: {local_list_invalid_app_ids}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # delete session for user
        global_object_square_database_helper.delete_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserSession.__tablename__,
            filters=FiltersV0(
                root={
                    UserSession.user_id.name: FilterConditionsV0(eq=user_id),
                    UserSession.app_id.name: FilterConditionsV0(in_=app_ids),
                }
            ),
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["LOGOUT_SUCCESSFUL"],
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.delete("/logout/all/v0")
@global_object_square_logger.auto_logger()
async def logout_all_v0(
    access_token: Annotated[str, Header()],
):

    try:
        """
        validation
        """
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

        """
        main process
        """
        # delete session for user
        global_object_square_database_helper.delete_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserSession.__tablename__,
            filters=FiltersV0(
                root={
                    UserSession.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["LOGOUT_SUCCESSFUL"],
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.patch("/update_username/v0")
@global_object_square_logger.auto_logger()
async def update_username_v0(
    new_username: str,
    access_token: Annotated[str, Header()],
):
    try:
        """
        validation
        """
        # validate access token
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

        # validation for username
        new_username = new_username.lower()
        username_pattern = re.compile(r"^[a-z0-9._-]{2,20}$")
        if not username_pattern.match(new_username):
            output_content = get_api_output_in_standard_format(
                message=messages["USERNAME_INVALID"],
                log=f"username '{new_username}' is invalid. it must start and end with a letter, "
                f"contain only lowercase letters, numbers, underscores, or hyphens, "
                f"and not have consecutive separators.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate user_id
        local_list_user_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(
                root={
                    User.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
        )["data"]["main"]

        if len(local_list_user_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USER_ID"],
                log=f"incorrect user_id: {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate new username
        local_list_user_credentials_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters=FiltersV0(
                    root={
                        User.user_username.name: FilterConditionsV0(eq=new_username),
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_user_credentials_response) != 0:
            output_content = get_api_output_in_standard_format(
                message=messages["USERNAME_ALREADY_EXISTS"],
                log=f"{new_username} is taken.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # edit the username
        global_object_square_database_helper.edit_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(
                root={
                    User.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
            data={
                User.user_username.name: new_username,
            },
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            data={"main": {"user_id": user_id, "username": new_username}},
            message=messages["GENERIC_UPDATE_SUCCESSFUL"],
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.post("/delete_user/v0")
@global_object_square_logger.auto_logger()
async def delete_user_v0(
    body: DeleteUserV0,
    access_token: Annotated[str, Header()],
):
    password = body.password
    try:
        """
        validation
        """
        # validate access token
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

        # validate user_id
        local_list_authentication_user_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserCredential.__tablename__,
                filters=FiltersV0(
                    root={UserCredential.user_id.name: FilterConditionsV0(eq=user_id)}
                ),
            )["data"]["main"]
        )
        if len(local_list_authentication_user_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USER_ID"],
                log=f"incorrect user_id: {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate password
        local_dict_user = local_list_authentication_user_response[0]
        if not (
            bcrypt.checkpw(
                password.encode("utf-8"),
                local_dict_user[
                    UserCredential.user_credential_hashed_password.name
                ].encode("utf-8"),
            )
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_PASSWORD"],
                log=f"incorrect password for user_id {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # delete the user.
        global_object_square_database_helper.delete_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(
                root={
                    User.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_DELETE_SUCCESSFUL"],
            log=f"user_id: {user_id} deleted successfully.",
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.patch("/update_password/v0")
@global_object_square_logger.auto_logger()
async def update_password_v0(
    body: UpdatePasswordV0,
    access_token: Annotated[str, Header()],
):
    old_password = body.old_password
    new_password = body.new_password
    try:
        """
        validation
        """
        # validate access token
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

        # validate user_id
        local_list_authentication_user_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserCredential.__tablename__,
                filters=FiltersV0(
                    root={UserCredential.user_id.name: FilterConditionsV0(eq=user_id)}
                ),
            )["data"]["main"]
        )
        if len(local_list_authentication_user_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USER_ID"],
                log=f"incorrect user_id: {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate password
        local_dict_user = local_list_authentication_user_response[0]
        if not (
            bcrypt.checkpw(
                old_password.encode("utf-8"),
                local_dict_user[
                    UserCredential.user_credential_hashed_password.name
                ].encode("utf-8"),
            )
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_PASSWORD"],
                log=f"incorrect password for user_id {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # update the password
        local_str_hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        global_object_square_database_helper.edit_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters=FiltersV0(
                root={
                    UserCredential.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
            data={
                UserCredential.user_credential_hashed_password.name: local_str_hashed_password,
            },
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_UPDATE_SUCCESSFUL"],
            log=f"password for user_id: {user_id} updated successfully.",
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.get("/validate_and_get_payload_from_token/v0")
@global_object_square_logger.auto_logger()
async def validate_and_get_payload_from_token_v0(
    token: Annotated[str, Header()],
    token_type: TokenType = Query(...),
):

    try:
        """
        validation
        """
        # validate token
        try:
            local_dict_token_payload = None
            if token_type == TokenType.access_token:
                local_dict_token_payload = get_jwt_payload(
                    token, config_str_secret_key_for_access_token
                )
            elif token_type == TokenType.refresh_token:
                local_dict_token_payload = get_jwt_payload(
                    token, config_str_secret_key_for_refresh_token
                )
                local_list_response_user_session = global_object_square_database_helper.get_rows_v0(
                    database_name=global_string_database_name,
                    schema_name=global_string_schema_name,
                    table_name=UserSession.__tablename__,
                    filters=FiltersV0(
                        root={
                            UserSession.user_session_refresh_token.name: FilterConditionsV0(
                                eq=token
                            ),
                            UserSession.user_id.name: FilterConditionsV0(
                                eq=local_dict_token_payload["user_id"]
                            ),
                        }
                    ),
                )[
                    "data"
                ][
                    "main"
                ]
                if len(local_list_response_user_session) != 1:
                    output_content = get_api_output_in_standard_format(
                        message=messages["INCORRECT_REFRESH_TOKEN"],
                        log="refresh token valid but not present in database.",
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=output_content,
                    )
        except HTTPException as http_exception:
            raise
        except Exception as error:
            output_content = None
            if token_type == TokenType.access_token:
                output_content = get_api_output_in_standard_format(
                    message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
                )
            elif token_type == TokenType.refresh_token:
                output_content = get_api_output_in_standard_format(
                    message=messages["INCORRECT_REFRESH_TOKEN"], log=str(error)
                )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        """
        main process
        """
        # pass
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_READ_SUCCESSFUL"],
            data={"main": local_dict_token_payload},
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.patch("/update_user_recovery_methods/v0")
@global_object_square_logger.auto_logger()
async def update_user_recovery_methods_v0(
    access_token: Annotated[str, Header()],
    recovery_methods_to_add: List[RecoveryMethodEnum],
    recovery_methods_to_remove: List[RecoveryMethodEnum],
):
    try:

        """
        validation
        """
        # validate access token
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

        recovery_methods_to_add = list(set(x.value for x in recovery_methods_to_add))
        recovery_methods_to_remove = list(
            set(x.value for x in recovery_methods_to_remove)
        )

        # check if recovery_methods_to_add and recovery_methods_to_remove don't have common ids.
        local_list_common_recovery_methods = set(recovery_methods_to_add) & set(
            recovery_methods_to_remove
        )
        if len(local_list_common_recovery_methods) > 0:
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_400"],
                log=f"invalid recovery_methods: {list(local_list_common_recovery_methods)}, present in both add list and remove list.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        """
        main process
        """
        # logic for adding new recovery_methods
        local_list_response_user_recovery_methods = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserRecoveryMethod.__tablename__,
                filters=FiltersV0(
                    root={
                        UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id)
                    }
                ),
            )["data"]["main"]
        )
        local_list_new_recovery_methods = [
            {
                UserRecoveryMethod.user_id.name: user_id,
                UserRecoveryMethod.user_recovery_method_name.name: x,
            }
            for x in recovery_methods_to_add
            if x
            not in [
                y[UserRecoveryMethod.user_recovery_method_name.name]
                for y in local_list_response_user_recovery_methods
            ]
        ]
        if len(local_list_new_recovery_methods) > 0:
            global_object_square_database_helper.insert_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserRecoveryMethod.__tablename__,
                data=local_list_new_recovery_methods,
            )

        # logic for removing recovery_methods
        global_object_square_database_helper.delete_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserRecoveryMethod.__tablename__,
            filters=FiltersV0(
                root={
                    UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id),
                    UserRecoveryMethod.user_recovery_method_name.name: FilterConditionsV0(
                        in_=recovery_methods_to_remove
                    ),
                }
            ),
        )

        """
        return value
        """
        # get latest recovery_methods
        local_list_response_user_recovery_methods = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserRecoveryMethod.__tablename__,
                filters=FiltersV0(
                    root={
                        UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id)
                    }
                ),
            )["data"]["main"]
        )
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_UPDATE_SUCCESSFUL"],
            data={
                "main": [
                    x[UserRecoveryMethod.user_recovery_method_name.name]
                    for x in local_list_response_user_recovery_methods
                ]
            },
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=output_content,
        )


@router.post("/generate_account_backup_codes/v0")
@global_object_square_logger.auto_logger()
async def generate_account_backup_codes_v0(
    access_token: Annotated[str, Header()],
):

    try:
        """
        validation
        """
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_ACCESS_TOKEN"], log=str(error)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]
        # check if user has recovery method enabled
        local_list_response_user_recovery_methods = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserRecoveryMethod.__tablename__,
            filters=FiltersV0(
                root={
                    UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id),
                    UserRecoveryMethod.user_recovery_method_name.name: FilterConditionsV0(
                        eq=RecoveryMethodEnum.BACKUP_CODE.value
                    ),
                }
            ),
        )[
            "data"
        ][
            "main"
        ]
        if len(local_list_response_user_recovery_methods) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["RECOVERY_METHOD_NOT_ENABLED"],
                log=f"user_id: {user_id} does not have backup codes recovery method enabled.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # generate backup codes
        backup_codes = []
        db_data = []

        for i in range(10):
            backup_code = str(uuid.uuid4())
            backup_codes.append(backup_code)
            # hash the backup code
            local_str_hashed_backup_code = bcrypt.hashpw(
                backup_code.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

            db_data.append(
                {
                    UserVerificationCode.user_id.name: user_id,
                    UserVerificationCode.user_verification_code_type.name: VerificationCodeTypeEnum.BACKUP_CODE_RECOVERY.value,
                    UserVerificationCode.user_verification_code_hash.name: local_str_hashed_backup_code,
                }
            )
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            data=db_data,
        )

        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_CREATION_SUCCESSFUL"],
            data={
                "main": {
                    "user_id": user_id,
                    "backup_codes": backup_codes,
                }
            },
        )
        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.post("/reset_password_and_login_using_backup_code/v0")
@global_object_square_logger.auto_logger()
async def reset_password_and_login_using_backup_code_v0(
    body: ResetPasswordAndLoginUsingBackupCodeV0,
):
    backup_code = body.backup_code
    username = body.username
    new_password = body.new_password
    app_id = body.app_id
    try:
        """
        validation
        """
        # validate username
        local_list_authentication_user_response = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters=FiltersV0(
                    root={User.user_username.name: FilterConditionsV0(eq=username)}
                ),
            )["data"]["main"]
        )
        if len(local_list_authentication_user_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USERNAME"],
                log=f"incorrect username: {username}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        user_id = local_list_authentication_user_response[0][User.user_id.name]
        # check if user has recovery method enabled
        local_list_response_user_recovery_methods = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserRecoveryMethod.__tablename__,
            filters=FiltersV0(
                root={
                    UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id),
                    UserRecoveryMethod.user_recovery_method_name.name: FilterConditionsV0(
                        eq=RecoveryMethodEnum.BACKUP_CODE.value
                    ),
                }
            ),
        )[
            "data"
        ][
            "main"
        ]
        if len(local_list_response_user_recovery_methods) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["RECOVERY_METHOD_NOT_ENABLED"],
                log=f"user_id: {user_id} does not have backup codes recovery method enabled.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # validate if user is assigned to the app.
        # not checking [skipping] if the app exists, as it is not required for this endpoint.
        local_list_response_user_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={
                    UserApp.user_id.name: FilterConditionsV0(eq=user_id),
                    UserApp.app_id.name: FilterConditionsV0(eq=app_id),
                }
            ),
        )["data"]["main"]
        if len(local_list_response_user_app) == 0:
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_400"],
                log=f"user_id: {user_id} is not assigned to app_id: {app_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        # validate backup code
        local_list_response_user_verification_code = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.BACKUP_CODE_RECOVERY.value
                    ),
                    UserVerificationCode.user_verification_code_expires_at.name: FilterConditionsV0(
                        is_null=True
                    ),
                    UserVerificationCode.user_verification_code_used_at.name: FilterConditionsV0(
                        is_null=True
                    ),
                }
            ),
            columns=[UserVerificationCode.user_verification_code_hash.name],
        )[
            "data"
        ][
            "main"
        ]
        # find the backup code in the list
        local_list_response_user_verification_code = [
            x
            for x in local_list_response_user_verification_code
            if bcrypt.checkpw(
                backup_code.encode("utf-8"),
                x[UserVerificationCode.user_verification_code_hash.name].encode(
                    "utf-8"
                ),
            )
        ]
        if len(local_list_response_user_verification_code) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_BACKUP_CODE"],
                log=f"incorrect backup code: {backup_code} for user_id: {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # hash the new password
        local_str_hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        # update the password
        global_object_square_database_helper.edit_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters=FiltersV0(
                root={
                    UserCredential.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
            data={
                UserCredential.user_credential_hashed_password.name: local_str_hashed_password,
            },
        )
        # mark the backup code as used
        global_object_square_database_helper.edit_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.BACKUP_CODE_RECOVERY.value
                    ),
                    UserVerificationCode.user_verification_code_hash.name: FilterConditionsV0(
                        eq=local_list_response_user_verification_code[0][
                            UserVerificationCode.user_verification_code_hash.name
                        ]
                    ),
                }
            ),
            data={
                UserVerificationCode.user_verification_code_used_at.name: datetime.now(
                    timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S.%f+00"),
            },
        )
        # generate access token and refresh token
        local_dict_access_token_payload = {
            "app_id": app_id,
            "user_id": user_id,
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=config_int_access_token_valid_minutes),
        }
        local_str_access_token = jwt.encode(
            local_dict_access_token_payload, config_str_secret_key_for_access_token
        )
        local_object_refresh_token_expiry_time = datetime.now(timezone.utc) + timedelta(
            minutes=config_int_refresh_token_valid_minutes
        )
        local_dict_refresh_token_payload = {
            "app_id": app_id,
            "user_id": user_id,
            "exp": local_object_refresh_token_expiry_time,
        }
        local_str_refresh_token = jwt.encode(
            local_dict_refresh_token_payload, config_str_secret_key_for_refresh_token
        )
        # insert the refresh token in the database
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserSession.__tablename__,
            data=[
                {
                    UserSession.user_id.name: user_id,
                    UserSession.app_id.name: app_id,
                    UserSession.user_session_refresh_token.name: local_str_refresh_token,
                    UserSession.user_session_expiry_time.name: local_object_refresh_token_expiry_time.strftime(
                        "%Y-%m-%d %H:%M:%S.%f+00"
                    ),
                }
            ],
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_CREATION_SUCCESSFUL"],
            data={
                "main": {
                    "user_id": user_id,
                    "access_token": local_str_access_token,
                    "refresh_token": local_str_refresh_token,
                }
            },
        )

        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )
