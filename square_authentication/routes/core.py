import copy
import io
import mimetypes
import random
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, List

import bcrypt
import jwt
from fastapi import APIRouter, Header, HTTPException, status
from fastapi.params import Query
from fastapi.responses import JSONResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from requests import HTTPError
from square_commons import get_api_output_in_standard_format, send_email_using_mailgun
from square_commons.api_utils import make_request
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
from square_database_structure.square.email import (
    global_string_schema_name as email_schema_name,
)
from square_database_structure.square.email.enums import EmailTypeEnum, EmailStatusEnum
from square_database_structure.square.email.tables import EmailLog
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
    MAIL_GUN_API_KEY,
    GOOGLE_AUTH_PLATFORM_CLIENT_ID,
    NUMBER_OF_RECOVERY_CODES,
    NUMBER_OF_DIGITS_IN_EMAIL_PASSWORD_RESET_CODE,
    EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS,
    global_object_square_file_store_helper,
    RESEND_COOL_DOWN_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS,
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
    SendResetPasswordEmailV0,
    ResetPasswordAndLoginUsingResetEmailCodeV0,
    RegisterLoginGoogleV0,
)
from square_authentication.utils.core import generate_default_username_for_google_users
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


@router.post("/register_login_google/v0")
async def register_login_google_v0(body: RegisterLoginGoogleV0):
    app_id = body.app_id
    google_id = body.google_id
    assign_app_id_if_missing = body.assign_app_id_if_missing
    was_new_user = False
    try:
        """
        validation
        """
        # verify id token
        id_info = id_token.verify_oauth2_token(
            google_id,
            google_requests.Request(),
            GOOGLE_AUTH_PLATFORM_CLIENT_ID,
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
        # fetch user profile photo storage token
        user_profile_storage_token = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            filters=FiltersV0(
                root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
            columns=[UserProfile.user_profile_photo_storage_token.name],
        )["data"]["main"][0][UserProfile.user_profile_photo_storage_token.name]

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
        # delete profile photo if exists
        if user_profile_storage_token:
            try:
                global_object_square_file_store_helper.delete_file_v0(
                    list_file_storage_token=[user_profile_storage_token]
                )
            except HTTPError as he:
                global_object_square_logger.warning(
                    f"Failed to delete user profile photo with storage token {user_profile_storage_token}. "
                    f"Error: {he.response.text}",
                    exc_info=True,
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
    logout_other_sessions = body.logout_other_sessions
    preserve_session_refresh_token = body.preserve_session_refresh_token
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
        # check if user has SELF auth provider
        local_list_response_user_auth_provider = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserAuthProvider.__tablename__,
                filters=FiltersV0(
                    root={
                        UserAuthProvider.user_id.name: FilterConditionsV0(eq=user_id),
                        UserAuthProvider.auth_provider.name: FilterConditionsV0(
                            eq=AuthProviderEnum.SELF.value
                        ),
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_response_user_auth_provider) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_AUTH_PROVIDER"],
                log=f"user_id: {user_id} does not have {AuthProviderEnum.SELF.value} auth provider.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if user has credentials (might not be set in case of errors in registration.)
        local_list_response_user = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(root={User.user_id.name: FilterConditionsV0(eq=user_id)}),
        )["data"]["main"]
        if len(local_list_response_user) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["MALFORMED_USER"],
                log=f"user_id: {user_id} does not have credentials.",
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
        # check if provided refresh token is valid
        if preserve_session_refresh_token:
            local_dict_token_payload = get_jwt_payload(
                preserve_session_refresh_token, config_str_secret_key_for_refresh_token
            )
            local_list_response_user_session = global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserSession.__tablename__,
                filters=FiltersV0(
                    root={
                        UserSession.user_id.name: FilterConditionsV0(eq=user_id),
                        UserSession.user_session_refresh_token.name: FilterConditionsV0(
                            eq=preserve_session_refresh_token
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
                    log=f"incorrect refresh token: {preserve_session_refresh_token}.",
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
        if logout_other_sessions:
            if preserve_session_refresh_token:
                # delete all sessions for user except the one with the given refresh token
                global_object_square_database_helper.delete_rows_v0(
                    database_name=global_string_database_name,
                    schema_name=global_string_schema_name,
                    table_name=UserSession.__tablename__,
                    filters=FiltersV0(
                        root={
                            UserSession.user_id.name: FilterConditionsV0(eq=user_id),
                            UserSession.user_session_refresh_token.name: FilterConditionsV0(
                                ne=preserve_session_refresh_token
                            ),
                        }
                    ),
                )
            else:
                # delete all sessions for user
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
    app_id: int,
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
            if local_dict_token_payload["app_id"] != app_id:
                output_content = get_api_output_in_standard_format(
                    message=messages["GENERIC_400"],
                    log=f"app_id: {app_id} does not match with token app_id: {local_dict_token_payload['app_id']}.",
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
    recovery_methods_to_add: List[RecoveryMethodEnum] = None,
    recovery_methods_to_remove: List[RecoveryMethodEnum] = None,
):
    if recovery_methods_to_add is None:
        recovery_methods_to_add = []
    if recovery_methods_to_remove is None:
        recovery_methods_to_remove = []
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
        # check if user's email is verified in user profile.
        # maybe too harsh to reject the request entirely,
        # but for practical purposes this api call should be used for 1 recovery method at a time, so it's not too bad.
        if RecoveryMethodEnum.EMAIL.value in recovery_methods_to_add:
            local_list_response_user_profile = (
                global_object_square_database_helper.get_rows_v0(
                    database_name=global_string_database_name,
                    schema_name=global_string_schema_name,
                    table_name=UserProfile.__tablename__,
                    filters=FiltersV0(
                        root={
                            UserProfile.user_id.name: FilterConditionsV0(eq=user_id),
                        }
                    ),
                )["data"]["main"]
            )
            if len(local_list_response_user_profile) != 1:
                # maybe this should raise 500 as this error will not occur if code runs correctly.
                output_content = get_api_output_in_standard_format(
                    message=messages["GENERIC_400"],
                    log=f"user_id: {user_id} does not have a profile.",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=output_content,
                )
            local_dict_user_profile = local_list_response_user_profile[0]
            if not local_dict_user_profile[
                UserProfile.user_profile_email_verified.name
            ]:
                output_content = get_api_output_in_standard_format(
                    message=messages["EMAIL_NOT_VERIFIED"],
                    log=f"user_id: {user_id} does not have email verified.",
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
        remove_old_backup_codes = (
            RecoveryMethodEnum.BACKUP_CODE.value in recovery_methods_to_remove
        )
        old_backup_code_hashes = None
        if remove_old_backup_codes:
            # delete existing backup codes if any
            old_backup_code_hashes = global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserVerificationCode.__tablename__,
                filters=FiltersV0(
                    root={
                        UserVerificationCode.user_id.name: FilterConditionsV0(
                            eq=user_id
                        ),
                        UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                            eq=VerificationCodeTypeEnum.BACKUP_CODE_RECOVERY.value
                        ),
                    }
                ),
                columns=[UserVerificationCode.user_verification_code_hash.name],
            )["data"]["main"]
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
        if remove_old_backup_codes and old_backup_code_hashes:
            global_object_square_database_helper.delete_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserVerificationCode.__tablename__,
                filters=FiltersV0(
                    root={
                        UserVerificationCode.user_verification_code_hash.name: FilterConditionsV0(
                            in_=[
                                x[UserVerificationCode.user_verification_code_hash.name]
                                for x in old_backup_code_hashes
                            ]
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
        # delete existing backup codes if any
        old_backup_code_hashes = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.BACKUP_CODE_RECOVERY.value
                    ),
                }
            ),
            columns=[UserVerificationCode.user_verification_code_hash.name],
        )["data"]["main"]

        # generate backup codes
        backup_codes = []
        db_data = []

        for i in range(NUMBER_OF_RECOVERY_CODES):
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
        global_object_square_database_helper.delete_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_verification_code_hash.name: FilterConditionsV0(
                        in_=[
                            x[UserVerificationCode.user_verification_code_hash.name]
                            for x in old_backup_code_hashes
                        ]
                    ),
                }
            ),
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
    logout_other_sessions = body.logout_other_sessions
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
        # check if user has SELF auth provider
        local_list_response_user_auth_provider = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserAuthProvider.__tablename__,
                filters=FiltersV0(
                    root={
                        UserAuthProvider.user_id.name: FilterConditionsV0(eq=user_id),
                        UserAuthProvider.auth_provider.name: FilterConditionsV0(
                            eq=AuthProviderEnum.SELF.value
                        ),
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_response_user_auth_provider) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_AUTH_PROVIDER"],
                log=f"user_id: {user_id} does not have {AuthProviderEnum.SELF.value} auth provider.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
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
        if logout_other_sessions:
            # delete all sessions for user
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
            message=messages["GENERIC_ACTION_SUCCESSFUL"],
            data={
                "main": {
                    "user_id": user_id,
                    "access_token": local_str_access_token,
                    "refresh_token": local_str_refresh_token,
                    "refresh_token_expiry_time": local_object_refresh_token_expiry_time.isoformat(),
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


@router.post("/send_reset_password_email/v0")
@global_object_square_logger.auto_logger()
async def send_reset_password_email_v0(
    body: SendResetPasswordEmailV0,
):
    username = body.username
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
        # check if user has SELF auth provider
        local_list_response_user_auth_provider = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserAuthProvider.__tablename__,
                filters=FiltersV0(
                    root={
                        UserAuthProvider.user_id.name: FilterConditionsV0(eq=user_id),
                        UserAuthProvider.auth_provider.name: FilterConditionsV0(
                            eq=AuthProviderEnum.SELF.value
                        ),
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_response_user_auth_provider) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_AUTH_PROVIDER"],
                log=f"user_id: {user_id} does not have {AuthProviderEnum.SELF.value} auth provider.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if user has recovery method enabled
        local_list_response_user_recovery_methods = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserRecoveryMethod.__tablename__,
            filters=FiltersV0(
                root={
                    UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id),
                    UserRecoveryMethod.user_recovery_method_name.name: FilterConditionsV0(
                        eq=RecoveryMethodEnum.EMAIL.value
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
                log=f"user_id: {user_id} does not have email recovery method enabled.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # validate if user has email in profile
        user_profile_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            filters=FiltersV0(
                root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
            apply_filters=True,
        )
        user_profile_data = user_profile_response["data"]["main"][0]
        if not user_profile_data.get(UserProfile.user_profile_email.name):
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_MISSING_REQUIRED_FIELD"],
                log="email is required to send verification email.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if email is not verified
        if not user_profile_data.get(UserProfile.user_profile_email_verified.name):
            output_content = get_api_output_in_standard_format(
                message=messages["EMAIL_NOT_VERIFIED"],
                log="email is not verified.",
            )
            return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
        # check if reset password code already exists
        local_list_response_user_verification_code = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.EMAIL_RECOVERY.value
                    ),
                    UserVerificationCode.user_verification_code_used_at.name: FilterConditionsV0(
                        is_null=True
                    ),
                    UserVerificationCode.user_verification_code_expires_at.name: FilterConditionsV0(
                        gte=datetime.now(timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S.%f+00"
                        )
                    ),
                }
            ),
            order_by=[
                "-" + UserVerificationCode.user_verification_code_created_at.name
            ],
            limit=1,
            apply_filters=True,
        )[
            "data"
        ][
            "main"
        ]
        if len(local_list_response_user_verification_code) > 0:
            existing_verification_code_data = (
                local_list_response_user_verification_code[0]
            )
            if (
                datetime.now(timezone.utc)
                - datetime.fromisoformat(
                    existing_verification_code_data[
                        UserVerificationCode.user_verification_code_created_at.name
                    ]
                )
            ).total_seconds() < RESEND_COOL_DOWN_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS:
                output_content = get_api_output_in_standard_format(
                    message=messages["GENERIC_400"],
                    log="verification code already exists and was sent within the cooldown period.",
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=output_content,
                )
        """
        main process
        """
        verification_code = random.randint(
            10 ** (NUMBER_OF_DIGITS_IN_EMAIL_PASSWORD_RESET_CODE - 1),
            10**NUMBER_OF_DIGITS_IN_EMAIL_PASSWORD_RESET_CODE - 1,
        )
        # hash the verification code
        hashed_verification_code = bcrypt.hashpw(
            str(verification_code).encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS
        )
        # add verification code to UserVerification code table
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            data=[
                {
                    UserVerificationCode.user_id.name: user_id,
                    UserVerificationCode.user_verification_code_type.name: VerificationCodeTypeEnum.EMAIL_RECOVERY.value,
                    UserVerificationCode.user_verification_code_hash.name: hashed_verification_code,
                    UserVerificationCode.user_verification_code_expires_at.name: expires_at.strftime(
                        "%Y-%m-%d %H:%M:%S.%f+00"
                    ),
                }
            ],
        )
        # send verification email
        if (
            user_profile_data[UserProfile.user_profile_first_name.name]
            and user_profile_data[UserProfile.user_profile_last_name.name]
        ):
            user_to_name = f"{user_profile_data[UserProfile.user_profile_first_name.name]} {user_profile_data[UserProfile.user_profile_last_name.name]}"
        elif user_profile_data[UserProfile.user_profile_first_name.name]:
            user_to_name = user_profile_data[UserProfile.user_profile_first_name.name]
        elif user_profile_data[UserProfile.user_profile_last_name.name]:
            user_to_name = user_profile_data[UserProfile.user_profile_last_name.name]
        else:
            user_to_name = ""

        mailgun_response = send_email_using_mailgun(
            from_email="auth@thepmsquare.com",
            from_name="square_authentication",
            to_email=user_profile_data[UserProfile.user_profile_email.name],
            to_name=user_to_name,
            subject="Password Reset Verification Code",
            body=f"Your Password Reset verification code is {verification_code}. It will expire in {EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS/60} minutes.",
            api_key=MAIL_GUN_API_KEY,
            domain_name="thepmsquare.com",
        )
        # add log for email sending
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=email_schema_name,
            table_name=EmailLog.__tablename__,
            data=[
                {
                    EmailLog.user_id.name: user_id,
                    EmailLog.recipient_email.name: user_profile_data[
                        UserProfile.user_profile_email.name
                    ],
                    EmailLog.email_type.name: EmailTypeEnum.VERIFY_EMAIL.value,
                    EmailLog.status.name: EmailStatusEnum.SENT.value,
                    EmailLog.third_party_message_id.name: mailgun_response.get("id"),
                }
            ],
        )
        """
        return value
        """
        cooldown_reset_at = datetime.now(timezone.utc) + timedelta(
            seconds=EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS,
        )
        output_content = get_api_output_in_standard_format(
            data={
                "expires_at": expires_at.isoformat(),
                "cooldown_reset_at": cooldown_reset_at.isoformat(),
            },
            message=messages["GENERIC_ACTION_SUCCESSFUL"],
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


@router.post("/reset_password_and_login_using_reset_email_code/v0")
@global_object_square_logger.auto_logger()
async def reset_password_and_login_using_reset_email_code_v0(
    body: ResetPasswordAndLoginUsingResetEmailCodeV0,
):
    reset_email_code = body.reset_email_code
    username = body.username
    new_password = body.new_password
    app_id = body.app_id
    logout_other_sessions = body.logout_other_sessions
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
        # check if user has SELF auth provider
        local_list_response_user_auth_provider = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserAuthProvider.__tablename__,
                filters=FiltersV0(
                    root={
                        UserAuthProvider.user_id.name: FilterConditionsV0(eq=user_id),
                        UserAuthProvider.auth_provider.name: FilterConditionsV0(
                            eq=AuthProviderEnum.SELF.value
                        ),
                    }
                ),
            )["data"]["main"]
        )
        if len(local_list_response_user_auth_provider) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_AUTH_PROVIDER"],
                log=f"user_id: {user_id} does not have {AuthProviderEnum.SELF.value} auth provider.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if user has recovery method enabled
        local_list_response_user_recovery_methods = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserRecoveryMethod.__tablename__,
            filters=FiltersV0(
                root={
                    UserRecoveryMethod.user_id.name: FilterConditionsV0(eq=user_id),
                    UserRecoveryMethod.user_recovery_method_name.name: FilterConditionsV0(
                        eq=RecoveryMethodEnum.EMAIL.value
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
                log=f"user_id: {user_id} does not have email recovery method enabled.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if user has email in profile
        user_profile_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            filters=FiltersV0(
                root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
            apply_filters=True,
        )
        user_profile_data = user_profile_response["data"]["main"][0]
        if not user_profile_data.get(UserProfile.user_profile_email.name):
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_MISSING_REQUIRED_FIELD"],
                log="user seems to have email recovery method enabled, but does not have email in profile.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # check if email is verified.
        if not user_profile_data.get(UserProfile.user_profile_email_verified.name):
            output_content = get_api_output_in_standard_format(
                message=messages["EMAIL_NOT_VERIFIED"],
                log="email is not verified.",
            )
            return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
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
        # validate email reset code
        local_list_response_user_verification_code = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.EMAIL_RECOVERY.value
                    ),
                    UserVerificationCode.user_verification_code_expires_at.name: FilterConditionsV0(
                        gte=datetime.now(timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S.%f+00"
                        )
                    ),
                    UserVerificationCode.user_verification_code_used_at.name: FilterConditionsV0(
                        is_null=True
                    ),
                }
            ),
            columns=[UserVerificationCode.user_verification_code_hash.name],
            order_by=[
                "-" + UserVerificationCode.user_verification_code_created_at.name
            ],
            limit=1,
        )[
            "data"
        ][
            "main"
        ]
        if len(local_list_response_user_verification_code) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_VERIFICATION_CODE"],
                log=f"incorrect reset_email_code: {reset_email_code} for user_id: {user_id}.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        latest_hashed_verification_code = local_list_response_user_verification_code[0][
            UserVerificationCode.user_verification_code_hash.name
        ]

        if not bcrypt.checkpw(
            reset_email_code.encode("utf-8"),
            latest_hashed_verification_code.encode("utf-8"),
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_VERIFICATION_CODE"],
                log=f"incorrect reset_email_code: {reset_email_code} for user_id: {user_id}.",
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
        # mark the email code as used
        global_object_square_database_helper.edit_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.EMAIL_RECOVERY.value
                    ),
                    UserVerificationCode.user_verification_code_hash.name: FilterConditionsV0(
                        eq=latest_hashed_verification_code
                    ),
                }
            ),
            data={
                UserVerificationCode.user_verification_code_used_at.name: datetime.now(
                    timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S.%f+00"),
            },
        )
        if logout_other_sessions:
            # delete all sessions for user
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
            message=messages["GENERIC_ACTION_SUCCESSFUL"],
            data={
                "main": {
                    "user_id": user_id,
                    "access_token": local_str_access_token,
                    "refresh_token": local_str_refresh_token,
                    "refresh_token_expiry_time": local_object_refresh_token_expiry_time.isoformat(),
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
