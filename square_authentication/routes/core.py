from datetime import datetime, timedelta, timezone
from typing import Annotated, List

import bcrypt
import jwt
from fastapi import APIRouter, status, Header, HTTPException
from fastapi.params import Query
from fastapi.responses import JSONResponse
from requests import HTTPError
from square_commons import get_api_output_in_standard_format
from square_database_helper.main import SquareDatabaseHelper
from square_database_helper.pydantic_models import (
    FiltersV0,
    FilterConditionsV0,
)
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
from square_authentication.messages import messages
from square_authentication.pydantic_models.core import (
    RegisterUsernameV0,
    LoginUsernameV0,
    DeleteUserV0,
    UpdatePasswordV0,
    TokenType,
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


@router.post("/register_username/v0")
@global_object_square_logger.async_auto_logger
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
        local_list_response_user_creds = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters=FiltersV0(
                root={
                    UserCredential.user_credential_username.name: FilterConditionsV0(
                        eq=username
                    )
                }
            ),
        )[
            "data"
        ][
            "main"
        ]
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
            data=[{}],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
        )["data"]["main"]
        local_str_user_id = local_list_response_user[0][User.user_id.name]

        # entry in credential table

        # hash password
        local_str_hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        global_object_square_database_helper.insert_rows_v0(
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
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]
        """
        main process
        """
        local_list_response_user_app = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserApp.__tablename__,
            filters=FiltersV0(
                root={UserApp.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
        )["data"]["main"]
        local_list_response_user_credentials = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserCredential.__tablename__,
                filters=FiltersV0(
                    root={UserCredential.user_id.name: FilterConditionsV0(eq=user_id)}
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
        """
        return value
        """
        return_this = {
            "user_id": user_id,
            "credentials": {
                "username": local_list_response_user_credentials[0][
                    UserCredential.user_credential_username.name
                ],
            },
            "apps": [x[UserApp.app_id.name] for x in local_list_response_user_app],
            "sessions": [
                {
                    "app_id": x[UserApp.app_id.name],
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
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
@global_object_square_logger.async_auto_logger
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
        local_list_authentication_user_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters=FiltersV0(
                root={
                    UserCredential.user_credential_username.name: FilterConditionsV0(
                        eq=username
                    )
                }
            ),
        )[
            "data"
        ][
            "main"
        ]
        if len(local_list_authentication_user_response) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_USERNAME"],
                log=f"incorrect username {username}",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=output_content
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
                    return JSONResponse(
                        status_code=he.response.status_code, content=output_content
                    )
            else:
                output_content = get_api_output_in_standard_format(
                    message=messages["GENERIC_400"],
                    log=f"user_id {local_str_user_id}({username}) not assigned to app {app_id}.",
                )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST, content=output_content
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
            )
        # validating if the refresh token is valid, active and of the same user.
        try:
            local_dict_refresh_token_payload = get_jwt_payload(
                refresh_token, config_str_secret_key_for_refresh_token
            )
        except Exception as error:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_REFRESH_TOKEN"],
                log=str(error),
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
            )
        user_id = local_dict_access_token_payload["user_id"]

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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
            )

        # validate new username
        local_list_user_credentials_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserCredential.__tablename__,
            filters=FiltersV0(
                root={
                    UserCredential.user_credential_username.name: FilterConditionsV0(
                        eq=new_username
                    ),
                }
            ),
        )[
            "data"
        ][
            "main"
        ]
        if len(local_list_user_credentials_response) != 0:
            output_content = get_api_output_in_standard_format(
                message=messages["USERNAME_ALREADY_EXISTS"],
                log=f"{new_username} is taken.",
            )
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content=output_content,
            )
        """
        main process
        """
        # edit the username
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
                UserCredential.user_credential_username.name: new_username,
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


@router.delete("/delete_user/v0")
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=output_content
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
@global_object_square_logger.async_auto_logger
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST, content=output_content
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
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
            )
        """
        main process
        """
        # delete the user.
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
@global_object_square_logger.async_auto_logger
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
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content=output_content,
                    )

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

            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=output_content,
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
