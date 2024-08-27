from datetime import datetime, timedelta, timezone
from typing import Annotated, Union

import bcrypt
import jwt
from fastapi import APIRouter, status, Header
from fastapi.responses import JSONResponse
from requests.exceptions import HTTPError
from square_database_helper.main import SquareDatabaseHelper
from square_database_structure.square.authentication.enums import UserLogEventEnum
from square_database_structure.square.authentication.tables import (
    local_string_database_name,
    local_string_schema_name,
    User,
    UserLog,
    UserCredential,
    UserProfile,
    UserSession,
)

from square_authentication.configuration import (
    global_object_square_logger,
    config_str_secret_key_for_access_token,
    config_int_access_token_valid_minutes,
    config_int_refresh_token_valid_minutes,
    config_str_secret_key_for_refresh_token,
    config_str_square_database_ip,
    config_int_square_database_port,
    config_str_square_database_protocol,
)
from square_authentication.utils.token import get_jwt_payload

router = APIRouter(
    tags=["core"],
)

global_object_square_database_helper = SquareDatabaseHelper(
    param_str_square_database_ip=config_str_square_database_ip,
    param_int_square_database_port=config_int_square_database_port,
    param_str_square_database_protocol=config_str_square_database_protocol,
)


@router.get("/register_username/")
@global_object_square_logger.async_auto_logger
async def register_username(username: str, password: str):
    local_str_user_id = None
    try:
        # ======================================================================================
        # entry in user table
        local_list_response_user = global_object_square_database_helper.insert_rows(
            data=[{}],
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=User.__tablename__,
        )
        local_str_user_id = local_list_response_user[0][User.user_id.name]
        # ======================================================================================

        # ======================================================================================
        # entry in user log
        local_list_response_user_log = global_object_square_database_helper.insert_rows(
            data=[
                {
                    UserLog.user_id.name: local_str_user_id,
                    UserLog.user_log_event.name: UserLogEventEnum.CREATED.value,
                }
            ],
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=UserLog.__tablename__,
        )
        # ======================================================================================

        # ======================================================================================
        # entry in user profile
        local_list_response_user_profile = (
            global_object_square_database_helper.insert_rows(
                data=[{UserProfile.user_id.name: local_str_user_id}],
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=UserProfile.__tablename__,
            )
        )

        # ======================================================================================

        # ======================================================================================
        # entry in credential table

        # hash password
        local_str_hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # create access token
        local_dict_access_token_payload = {
            "user_id": local_str_user_id,
            "exp": datetime.now(timezone.utc)
                   + timedelta(minutes=config_int_access_token_valid_minutes),
        }
        local_str_access_token = jwt.encode(
            local_dict_access_token_payload, config_str_secret_key_for_access_token
        )

        # create refresh token
        local_object_refresh_token_expiry_time = datetime.now(timezone.utc) + timedelta(
            minutes=config_int_refresh_token_valid_minutes
        )

        local_dict_refresh_token_payload = {
            "user_id": local_str_user_id,
            "exp": local_object_refresh_token_expiry_time,
        }
        local_str_refresh_token = jwt.encode(
            local_dict_refresh_token_payload, config_str_secret_key_for_refresh_token
        )
        try:
            local_list_response_authentication_username = global_object_square_database_helper.insert_rows(
                data=[
                    {
                        UserCredential.user_id.name: local_str_user_id,
                        UserCredential.user_credential_username.name: username,
                        UserCredential.user_credential_hashed_password.name: local_str_hashed_password,
                    }
                ],
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=UserCredential.__tablename__,
            )
        except HTTPError as http_error:
            if http_error.response.status_code == 400:
                return JSONResponse(
                    status_code=status.HTTP_409_CONFLICT,
                    content=f"an account with the username {username} already exists.",
                )
            else:
                raise http_error
        # ======================================================================================

        # ======================================================================================
        # entry in user session table
        local_list_response_user_session = global_object_square_database_helper.insert_rows(
            data=[
                {
                    UserSession.user_id.name: local_str_user_id,
                    UserSession.user_session_refresh_token.name: local_str_refresh_token,
                    UserSession.user_session_expiry_time.name: local_object_refresh_token_expiry_time.strftime(
                        "%Y-%m-%d %H:%M:%S.%f+00"
                    ),
                }
            ],
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=UserSession.__tablename__,
        )
        # ======================================================================================
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "user_id": local_str_user_id,
                "access_token": local_str_access_token,
                "refresh_token": local_str_refresh_token,
            },
        )
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        if local_str_user_id:
            global_object_square_database_helper.delete_rows(
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=User.__tablename__,
                filters={User.user_id.name: local_str_user_id},
            )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )


@router.get("/login_username/")
@global_object_square_logger.async_auto_logger
async def login_username(username: str, password: str):
    try:
        # ======================================================================================
        # get entry from authentication_username table
        local_list_authentication_user_response = (
            global_object_square_database_helper.get_rows(
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=UserCredential.__tablename__,
                filters={UserCredential.user_credential_username.name: username},
            )
        )
        # ======================================================================================

        # ======================================================================================
        # validate username
        # ======================================================================================
        if len(local_list_authentication_user_response) != 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content="incorrect username."
            )
        # ======================================================================================
        # validate password
        # ======================================================================================
        else:
            if not (
                    bcrypt.checkpw(
                        password.encode("utf-8"),
                        local_list_authentication_user_response[0][
                            UserCredential.user_credential_hashed_password.name
                        ].encode("utf-8"),
                    )
            ):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content="incorrect password.",
                )

            # ======================================================================================
            # return new access token and refresh token
            # ======================================================================================
            else:
                local_str_user_id = local_list_authentication_user_response[0][
                    UserCredential.user_id.name
                ]
                # create access token
                local_dict_access_token_payload = {
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
                    "user_id": local_str_user_id,
                    "exp": local_object_refresh_token_expiry_time,
                }
                local_str_refresh_token = jwt.encode(
                    local_dict_refresh_token_payload,
                    config_str_secret_key_for_refresh_token,
                )
                # ======================================================================================
                # entry in user session table
                local_list_response_user_session = global_object_square_database_helper.insert_rows(
                    data=[
                        {
                            UserSession.user_id.name: local_str_user_id,
                            UserSession.user_session_refresh_token.name: local_str_refresh_token,
                            UserSession.user_session_expiry_time.name: local_object_refresh_token_expiry_time.strftime(
                                "%Y-%m-%d %H:%M:%S.%f+00"
                            ),
                        }
                    ],
                    database_name=local_string_database_name,
                    schema_name=local_string_schema_name,
                    table_name=UserSession.__tablename__,
                )
                # ======================================================================================
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "user_id": local_str_user_id,
                        "access_token": local_str_access_token,
                        "refresh_token": local_str_refresh_token,
                    },
                )
        # ======================================================================================

    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )


@router.get("/generate_access_token/")
@global_object_square_logger.async_auto_logger
async def generate_access_token(
        user_id: str, refresh_token: Annotated[Union[str, None], Header()]
):
    try:
        # ======================================================================================
        # validate user_id
        local_list_user_response = global_object_square_database_helper.get_rows(
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=User.__tablename__,
            filters={User.user_id.name: user_id},
        )

        if len(local_list_user_response) != 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=f"incorrect user_id: {user_id}.",
            )
        # ======================================================================================

        # ======================================================================================
        # validate refresh token

        # validating if a session refresh token exists in the database.
        local_list_user_session_response = (
            global_object_square_database_helper.get_rows(
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=UserSession.__tablename__,
                filters={
                    UserSession.user_id.name: user_id,
                    UserSession.user_session_refresh_token.name: refresh_token,
                },
            )
        )

        if len(local_list_user_session_response) != 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=f"incorrect refresh token: {refresh_token} for user_id: {user_id}."
                        f"for user_id: {user_id}.",
            )
        # validating if the refresh token is valid, active and of the same user.
        try:
            local_dict_refresh_token_payload = get_jwt_payload(
                refresh_token, config_str_secret_key_for_refresh_token
            )
        except Exception as error:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=str(error),
            )

        if local_dict_refresh_token_payload["user_id"] != user_id:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=f"refresh token and user_id mismatch.",
            )

        # ======================================================================================
        # ======================================================================================
        # create and send access token
        local_dict_access_token_payload = {
            "user_id": user_id,
            "exp": datetime.now(timezone.utc)
                   + timedelta(minutes=config_int_access_token_valid_minutes),
        }
        local_str_access_token = jwt.encode(
            local_dict_access_token_payload, config_str_secret_key_for_access_token
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"access_token": local_str_access_token},
        )
        # ======================================================================================

    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )


@router.delete("/logout/")
@global_object_square_logger.async_auto_logger
async def logout(
        user_id: str,
        access_token: Annotated[Union[str, None], Header()],
        refresh_token: Annotated[Union[str, None], Header()],
):
    try:
        # ======================================================================================
        # validate user_id
        local_list_user_response = global_object_square_database_helper.get_rows(
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=User.__tablename__,
            filters={User.user_id.name: user_id},
        )

        if len(local_list_user_response) != 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=f"incorrect user_id: {user_id}.",
            )
        # ======================================================================================

        # ======================================================================================
        # validate refresh token

        # validating if a session refresh token exists in the database.
        local_list_user_session_response = (
            global_object_square_database_helper.get_rows(
                database_name=local_string_database_name,
                schema_name=local_string_schema_name,
                table_name=UserSession.__tablename__,
                filters={
                    UserSession.user_id.name: user_id,
                    UserSession.user_session_refresh_token.name: refresh_token,
                },
            )
        )

        if len(local_list_user_session_response) != 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=f"incorrect refresh token: {refresh_token} for user_id: {user_id}."
                        f"for user_id: {user_id}.",
            )
        # not validating if the refresh token is valid, active and of the same user.
        # ======================================================================================

        # ======================================================================================
        # validate access token
        # validating if the access token is valid, active and of the same user.
        try:
            local_dict_access_token_payload = get_jwt_payload(
                access_token, config_str_secret_key_for_access_token
            )
        except Exception as error:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=str(error),
            )
        if local_dict_access_token_payload["user_id"] != user_id:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=f"access token and user_id mismatch.",
            )

        # ======================================================================================

        # NOTE: if both access token and refresh token have expired for a user,
        # it can be assumed that user session only needs to be removed from the front end.

        # ======================================================================================
        # delete session for user
        global_object_square_database_helper.delete_rows(
            database_name=local_string_database_name,
            schema_name=local_string_schema_name,
            table_name=UserSession.__tablename__,
            filters={
                UserSession.user_id.name: user_id,
                UserSession.user_session_refresh_token.name: refresh_token,
            },
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK, content="Log out successful."
        )
        # ======================================================================================

    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )
