from datetime import datetime, timedelta, timezone
from typing import Annotated, Union, List
from uuid import UUID

import bcrypt
import jwt
from fastapi import APIRouter, status, Header, HTTPException
from fastapi.responses import JSONResponse
from square_database_helper.main import SquareDatabaseHelper
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.tables import (
    User,
    UserCredential,
    UserSession,
    UserApp,
)
from square_database_structure.square.public import (
    global_string_schema_name as global_string_public_schema_name,
)
from square_database_structure.square.public.tables import App

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


@router.post("/register_username/")
@global_object_square_logger.async_auto_logger
async def register_username(username: str, password: str):
    local_str_user_id = None
    username = username.lower()
    try:
        """
        validation
        """

        # validation for username
        local_list_response_user_creds = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters={UserCredential.user_credential_username.name: username},
        )
        if len(local_list_response_user_creds) > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"an account with the username {username} already exists.",
            )

        """
        main process
        """
        # entry in user table
        local_list_response_user = global_object_square_database_helper.insert_rows(
            data=[{}],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
        )
        local_str_user_id = local_list_response_user[0][User.user_id.name]

        # entry in credential table

        # hash password
        local_str_hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        global_object_square_database_helper.insert_rows(
            data=[
                {
                    UserCredential.user_id.name: local_str_user_id,
                    UserCredential.user_credential_username.name: username,
                    UserCredential.user_credential_hashed_password.name: local_str_hashed_password,
                }
            ],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
        )

        """
        return value
        """
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"user_id": local_str_user_id, "username": username},
        )
    except HTTPException as http_exception:
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        """
        rollback logic
        """
        if local_str_user_id:
            global_object_square_database_helper.delete_rows(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters={User.user_id.name: local_str_user_id},
            )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )


@router.get("/get_user_app_ids")
@global_object_square_logger.async_auto_logger
async def get_user_app_ids(user_id: UUID):
    try:
        local_string_user_id = str(user_id)
        """
        validation
        """

        local_list_response_user = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters={User.user_id.name: local_string_user_id},
        )
        if len(local_list_response_user) != 1:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"invalid user_id: {local_string_user_id}",
            )
        """
        main process
        """
        local_list_response_user_app = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters={UserApp.user_id.name: local_string_user_id},
        )
        """
        return value
        """
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=[x[UserApp.app_id.name] for x in local_list_response_user_app],
        )
    except HTTPException as http_exception:
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )


@router.patch("/update_user_app_ids")
@global_object_square_logger.async_auto_logger
async def update_user_app_ids(
        user_id: UUID,
        app_ids_to_add: List[int],
        app_ids_to_remove: List[int],
):
    try:
        local_string_user_id = str(user_id)
        """
        validation
        """

        # check if app_ids_to_add and app_ids_to_remove don't have common ids.
        local_list_common_app_ids = set(app_ids_to_add) & set(app_ids_to_remove)
        if len(local_list_common_app_ids) > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid app_ids: {list(local_list_common_app_ids)}, present in both add list and remove list.",
            )
        # validate access token
        # TBD

        # check if user id is in user table
        local_list_response_user = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters={User.user_id.name: local_string_user_id},
        )
        if len(local_list_response_user) != 1:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"invalid user_id: {local_string_user_id}",
            )

        # check if all app_ids are valid
        local_list_all_app_ids = [*app_ids_to_add, *app_ids_to_remove]
        local_list_response_app = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_public_schema_name,
            table_name=App.__tablename__,
            ignore_filters_and_get_all=True,
            filters={},
        )
        local_list_invalid_ids = [
            x
            for x in local_list_all_app_ids
            if x not in [y[App.app_id.name] for y in local_list_response_app]
        ]
        if len(local_list_invalid_ids) > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid app_ids: {local_list_invalid_ids}.",
            )
        """
        main process
        """
        # logic for adding new app_ids
        local_list_response_user_app = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters={UserApp.user_id.name: local_string_user_id},
        )
        local_list_new_app_ids = [
            {
                UserApp.user_id.name: local_string_user_id,
                UserApp.app_id.name: x,
            }
            for x in app_ids_to_add
            if x not in [y[UserApp.app_id.name] for y in local_list_response_user_app]
        ]
        global_object_square_database_helper.insert_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            data=local_list_new_app_ids,
        )

        # logic for removing app_ids
        for app_id in app_ids_to_remove:
            global_object_square_database_helper.delete_rows(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserApp.__tablename__,
                filters={
                    UserApp.user_id.name: local_string_user_id,
                    UserApp.app_id.name: app_id,
                },
            )

        """
        return value
        """
        # get latest app ids
        local_list_response_user_app = global_object_square_database_helper.get_rows(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters={UserApp.user_id.name: local_string_user_id},
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=[x[UserApp.app_id.name] for x in local_list_response_user_app],
        )
    except HTTPException as http_exception:
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        """
        rollback logic
        """
        global_object_square_logger.logger.error(e, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=str(e)
        )


@router.get("/login_username/")
@global_object_square_logger.async_auto_logger
async def login_username(username: str, password: str):
    username = username.lower()
    try:
        # ======================================================================================
        # get entry from authentication_username table
        local_list_authentication_user_response = (
            global_object_square_database_helper.get_rows(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
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
                    database_name=global_string_database_name,
                    schema_name=global_string_schema_name,
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
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
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
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
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
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
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
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
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
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
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
