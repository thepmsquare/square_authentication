import copy
import io
import mimetypes
import re
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from requests import HTTPError
from square_commons import get_api_output_in_standard_format
from square_commons.api_utils import make_request
from square_database_helper.pydantic_models import FilterConditionsV0, FiltersV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.enums import (
    AuthProviderEnum,
)
from square_database_structure.square.authentication.tables import (
    User,
    UserApp,
    UserCredential,
    UserSession,
    UserProfile,
    UserAuthProvider,
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
    GOOGLE_AUTH_PLATFORM_CLIENT_ID,
    global_object_square_file_store_helper,
)
from square_authentication.messages import messages
from square_authentication.utils.core import generate_default_username_for_google_users
from square_authentication.utils.token import get_jwt_payload


def util_register_username_v0(username, password, app_id):
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
        global_object_square_database_helper.insert_rows_v0(
            data=[
                {
                    UserAuthProvider.user_id.name: local_str_user_id,
                    UserAuthProvider.auth_provider.name: AuthProviderEnum.SELF.value,
                }
            ],
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserAuthProvider.__tablename__,
        )

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


def util_register_login_google_v0(google_id, assign_app_id_if_missing, app_id):
    was_new_user = False
    try:
        """
        validation
        """
        # verify id token
        try:
            id_info = id_token.verify_oauth2_token(
                google_id,
                google_requests.Request(),
                GOOGLE_AUTH_PLATFORM_CLIENT_ID,
            )
        except Exception:
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_400"],
                log="Google id is invalid.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate if email is verified
        if id_info.get("email_verified") is not True:
            output_content = get_api_output_in_standard_format(
                message=messages["EMAIL_NOT_VERIFIED"],
                log="Google account email is not verified.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        processing
        """
        google_sub = id_info["sub"]
        email = id_info.get("email")
        given_name = id_info.get("given_name")
        family_name = id_info.get("family_name")

        profile_picture = id_info.get("picture")

        # check if user exists
        user_rows = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserAuthProvider.__tablename__,
            filters=FiltersV0(
                root={
                    UserAuthProvider.auth_provider_user_id.name: FilterConditionsV0(
                        eq=google_sub
                    ),
                    UserAuthProvider.auth_provider.name: FilterConditionsV0(
                        eq=AuthProviderEnum.GOOGLE.value
                    ),
                }
            ),
        )["data"]["main"]

        if user_rows:
            # login

            # validate if app_id is assigned to user
            # this will also validate if app_id is valid
            local_str_user_id = user_rows[0][User.user_id.name]
            user_record = global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters=FiltersV0(
                    root={User.user_id.name: FilterConditionsV0(eq=local_str_user_id)}
                ),
            )["data"]["main"][0]
            username = user_record[User.user_username.name]
            local_list_user_app_response = (
                global_object_square_database_helper.get_rows_v0(
                    database_name=global_string_database_name,
                    schema_name=global_string_schema_name,
                    table_name=UserApp.__tablename__,
                    filters=FiltersV0(
                        root={
                            UserApp.user_id.name: FilterConditionsV0(
                                eq=local_str_user_id
                            ),
                            UserApp.app_id.name: FilterConditionsV0(eq=app_id),
                        }
                    ),
                )["data"]["main"]
            )
            if len(local_list_user_app_response) == 0:
                if assign_app_id_if_missing:
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
                else:
                    output_content = get_api_output_in_standard_format(
                        message=messages["GENERIC_400"],
                        log=f"user_id {local_str_user_id}({username}) not assigned to app {app_id}.",
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=output_content,
                    )
        else:
            # register

            was_new_user = True
            # check if account with same email address exists
            profile_rows = global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserProfile.__tablename__,
                filters=FiltersV0(
                    root={
                        UserProfile.user_profile_email.name: FilterConditionsV0(
                            eq=email
                        )
                    }
                ),
            )["data"]["main"]
            if len(profile_rows) > 0:
                output_content = get_api_output_in_standard_format(
                    message=messages["ACCOUNT_WITH_EMAIL_ALREADY_EXISTS"],
                    log=f"An account with the email {email} already exists.",
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=output_content,
                )
            # generate a default username
            username = generate_default_username_for_google_users(
                family_name=family_name, given_name=given_name
            )
            # create user
            user_rows = global_object_square_database_helper.insert_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                data=[
                    {
                        User.user_username.name: username,
                    }
                ],
            )["data"]["main"]
            local_str_user_id = user_rows[0][User.user_id.name]

            # link to user_auth_provider
            global_object_square_database_helper.insert_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserAuthProvider.__tablename__,
                data=[
                    {
                        UserAuthProvider.user_id.name: local_str_user_id,
                        UserAuthProvider.auth_provider.name: AuthProviderEnum.GOOGLE.value,
                        UserAuthProvider.auth_provider_user_id.name: google_sub,
                    }
                ],
            )
            # getting profile picture
            if profile_picture:
                try:
                    profile_picture_response = make_request(
                        "GET", profile_picture, return_type="response"
                    )

                    # finding content type and filename
                    headers = profile_picture_response.headers
                    content_type = headers.get(
                        "Content-Type", "application/octet-stream"
                    )
                    content_disposition = headers.get("Content-Disposition", "")

                    if content_disposition:
                        match = re.search(r'filename="([^"]+)"', content_disposition)
                        if match:
                            filename = match.group(1)
                        else:
                            filename = None
                    else:
                        filename = None
                    if filename is None:
                        global_object_square_logger.logger.warning(
                            f"user_id {local_str_user_id}'s profile picture from Google missing filename; guessing extension from Content-Type: {content_type}."
                        )
                        ext = (
                            mimetypes.guess_extension(
                                content_type.split(";")[0].strip()
                            )
                            or ""
                        )
                        filename = f"profile_photo{ext}"
                        if not ext:
                            filename += ".bin"

                    # upload bytes to square_file_storage
                    file_upload_response = global_object_square_file_store_helper.upload_file_using_tuple_v0(
                        file=(
                            filename,
                            io.BytesIO(profile_picture_response.content),
                            content_type,
                        ),
                        system_relative_path="global/users/profile_photos",
                    )
                    user_profile_photo_storage_token = file_upload_response["data"][
                        "main"
                    ]
                except HTTPError:
                    global_object_square_logger.logger.error(
                        f"Failed to fetch profile picture for user_id {local_str_user_id} from google account.",
                        exc_info=True,
                    )
                    user_profile_photo_storage_token = None
                except Exception as e:
                    global_object_square_logger.logger.error(
                        f"Error while fetching profile picture for user_id {local_str_user_id} from google account: {str(e)}",
                        exc_info=True,
                    )
                    user_profile_photo_storage_token = None
            else:
                global_object_square_logger.logger.warning(
                    f"user_id {local_str_user_id} has no profile picture in google account."
                )
                user_profile_photo_storage_token = None
            # create user profile
            global_object_square_database_helper.insert_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserProfile.__tablename__,
                data=[
                    {
                        UserProfile.user_id.name: local_str_user_id,
                        UserProfile.user_profile_email.name: email,
                        UserProfile.user_profile_email_verified.name: datetime.now(
                            timezone.utc
                        ).strftime("%Y-%m-%d %H:%M:%S.%f+00"),
                        UserProfile.user_profile_first_name.name: given_name,
                        UserProfile.user_profile_last_name.name: family_name,
                        UserProfile.user_profile_photo_storage_token.name: user_profile_photo_storage_token,
                    }
                ],
            )

            # assign app if provided
            if app_id is not None:
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

        # generate tokens
        now = datetime.now(timezone.utc)
        access_token_payload = {
            "app_id": app_id,
            "user_id": local_str_user_id,
            "exp": now + timedelta(minutes=config_int_access_token_valid_minutes),
        }
        access_token_str = jwt.encode(
            access_token_payload,
            config_str_secret_key_for_access_token,
        )

        refresh_token_expiry = now + timedelta(
            minutes=config_int_refresh_token_valid_minutes
        )
        refresh_token_payload = {
            "app_id": app_id,
            "user_id": local_str_user_id,
            "exp": refresh_token_expiry,
        }
        refresh_token_str = jwt.encode(
            refresh_token_payload,
            config_str_secret_key_for_refresh_token,
        )

        # store refresh token
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserSession.__tablename__,
            data=[
                {
                    UserSession.user_id.name: local_str_user_id,
                    UserSession.app_id.name: app_id,
                    UserSession.user_session_refresh_token.name: refresh_token_str,
                    UserSession.user_session_expiry_time.name: refresh_token_expiry.strftime(
                        "%Y-%m-%d %H:%M:%S.%f+00"
                    ),
                }
            ],
        )
        """
        return value
        """
        if was_new_user:
            message = messages["REGISTRATION_SUCCESSFUL"]
        else:
            message = messages["LOGIN_SUCCESSFUL"]
        output_content = get_api_output_in_standard_format(
            message=message,
            data={
                "main": {
                    "user_id": local_str_user_id,
                    "username": username,
                    "app_id": app_id,
                    "access_token": access_token_str,
                    "refresh_token": refresh_token_str,
                    "refresh_token_expiry_time": refresh_token_expiry.isoformat(),
                    "was_new_user": was_new_user,
                },
            },
        )

        return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
    except HTTPError as http_error:
        global_object_square_logger.logger.error(http_error, exc_info=True)
        return JSONResponse(
            status_code=http_error.response.status_code,
            content=http_error.response.text,
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


def util_get_user_details_v0(access_token):
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
        local_list_user = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(
                root={
                    User.user_id.name: FilterConditionsV0(eq=user_id),
                }
            ),
        )["data"]["main"]
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
            "username": local_list_user[0][User.user_username.name],
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


def util_update_user_app_ids_v0(access_token, app_ids_to_add, app_ids_to_remove):
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


def util_login_username_v0(username, password, app_id, assign_app_id_if_missing):
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
                message=messages["MALFORMED_USER"],
                log=f"username: {username} does not have credentials set.",
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


def util_generate_access_token_v0(refresh_token):
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
