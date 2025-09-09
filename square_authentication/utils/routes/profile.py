import random
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format
from square_commons.email import send_email_using_mailgun
from square_database_helper import FiltersV0
from square_database_helper.pydantic_models import FilterConditionsV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.enums import (
    VerificationCodeTypeEnum,
)
from square_database_structure.square.authentication.tables import (
    UserProfile,
    UserVerificationCode,
)
from square_database_structure.square.email import (
    global_string_schema_name as email_schema_name,
)
from square_database_structure.square.email.enums import EmailStatusEnum, EmailTypeEnum
from square_database_structure.square.email.tables import EmailLog

from square_authentication.configuration import (
    EXPIRY_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS,
    MAIL_GUN_API_KEY,
    NUMBER_OF_DIGITS_IN_EMAIL_VERIFICATION_CODE,
    RESEND_COOL_DOWN_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS,
    config_str_secret_key_for_access_token,
    global_object_square_database_helper,
    global_object_square_logger,
)
from square_authentication.configuration import (
    global_object_square_file_store_helper,
)
from square_authentication.messages import messages
from square_authentication.utils.token import get_jwt_payload


@global_object_square_logger.auto_logger()
def util_update_profile_photo_v0(access_token, profile_photo):
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

        # validate file format
        if profile_photo and not profile_photo.filename.endswith(
            (".jpg", ".jpeg", ".png")
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["INVALID_FILE_FORMAT"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate file size
        file_size_limit_in_mib = 5
        if profile_photo and profile_photo.size > (
            file_size_limit_in_mib * 1024 * 1024
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["FILE_SIZE_EXCEEDS_LIMIT"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """
        old_profile_photo_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            filters=FiltersV0(
                root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
            apply_filters=True,
        )
        old_profile_photo_token = old_profile_photo_response["data"]["main"][0][
            "user_profile_photo_storage_token"
        ]

        if profile_photo:
            # uploading to square file store
            file_upload_response = (
                global_object_square_file_store_helper.upload_file_using_tuple_v0(
                    file=(
                        profile_photo.filename,
                        profile_photo.file,
                        profile_photo.content_type,
                    ),
                    system_relative_path="global/users/profile_photos",
                )
            )
            # updating user profile
            profile_update_response = global_object_square_database_helper.edit_rows_v0(
                data={
                    UserProfile.user_profile_photo_storage_token.name: file_upload_response[
                        "data"
                    ][
                        "main"
                    ]
                },
                filters=FiltersV0(
                    root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
                ),
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserProfile.__tablename__,
                apply_filters=True,
            )
        else:
            # updating user profile
            profile_update_response = global_object_square_database_helper.edit_rows_v0(
                data={UserProfile.user_profile_photo_storage_token.name: None},
                filters=FiltersV0(
                    root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
                ),
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=UserProfile.__tablename__,
                apply_filters=True,
            )

        if old_profile_photo_token:
            global_object_square_file_store_helper.delete_file_v0(
                [old_profile_photo_token]
            )

        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            data=profile_update_response["data"],
            message=messages["GENERIC_UPDATE_SUCCESSFUL"],
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


@global_object_square_logger.auto_logger()
def util_update_profile_details_v0(
    access_token,
    first_name,
    last_name,
    email,
    phone_number_country_code,
    phone_number,
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

        # validate email format
        if email and "@" not in email:
            output_content = get_api_output_in_standard_format(
                message=messages["INVALID_EMAIL_FORMAT"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate phone number format
        if phone_number and not phone_number.isdigit():
            output_content = get_api_output_in_standard_format(
                message=messages["INVALID_PHONE_NUMBER_FORMAT"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        if (phone_number and not phone_number_country_code) or (
            phone_number_country_code and not phone_number
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["GENERIC_MISSING_REQUIRED_FIELD"],
                log="both phone number and country code must be provided together.",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        """
        main process
        """
        profile_update_data = {}
        if first_name is not None:
            profile_update_data[UserProfile.user_profile_first_name.name] = first_name
        if last_name is not None:
            profile_update_data[UserProfile.user_profile_last_name.name] = last_name
        if email is not None:
            profile_update_data[UserProfile.user_profile_email.name] = email
        if phone_number is not None and phone_number_country_code is not None:
            profile_update_data[UserProfile.user_profile_phone_number.name] = (
                phone_number
            )
            profile_update_data[
                UserProfile.user_profile_phone_number_country_code.name
            ] = phone_number_country_code

        # updating user profile
        profile_update_response = global_object_square_database_helper.edit_rows_v0(
            data=profile_update_data,
            filters=FiltersV0(
                root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            apply_filters=True,
        )

        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            data=profile_update_response["data"],
            message=messages["GENERIC_UPDATE_SUCCESSFUL"],
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


@global_object_square_logger.auto_logger()
def util_send_verification_email_v0(access_token):
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
        # check if email is already verified
        if user_profile_data.get(UserProfile.user_profile_email_verified.name):
            output_content = get_api_output_in_standard_format(
                message=messages["EMAIL_ALREADY_VERIFIED"]
            )
            return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
        # check if email verification code already exists
        existing_verification_code_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.EMAIL_VERIFICATION.value
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
        )
        if len(existing_verification_code_response["data"]["main"]) > 0:
            existing_verification_code_data = existing_verification_code_response[
                "data"
            ]["main"][0]
            if (
                datetime.now(timezone.utc)
                - datetime.fromisoformat(
                    existing_verification_code_data[
                        UserVerificationCode.user_verification_code_created_at.name
                    ]
                )
            ).total_seconds() < RESEND_COOL_DOWN_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS:
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
            10 ** (NUMBER_OF_DIGITS_IN_EMAIL_VERIFICATION_CODE - 1),
            10**NUMBER_OF_DIGITS_IN_EMAIL_VERIFICATION_CODE - 1,
        )
        # hash the verification code
        hashed_verification_code = bcrypt.hashpw(
            str(verification_code).encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=EXPIRY_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS
        )
        # add verification code to UserVerification code table
        global_object_square_database_helper.insert_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            data=[
                {
                    UserVerificationCode.user_id.name: user_id,
                    UserVerificationCode.user_verification_code_type.name: VerificationCodeTypeEnum.EMAIL_VERIFICATION.value,
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
            subject="Email Verification",
            body=f"Your verification code is {verification_code}. It will expire in {EXPIRY_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS / 60} minutes.",
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
            seconds=RESEND_COOL_DOWN_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS
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


@global_object_square_logger.auto_logger()
def util_validate_email_verification_code_v0(access_token, verification_code):
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
        # check if email is already verified
        if user_profile_data.get(UserProfile.user_profile_email_verified.name):
            output_content = get_api_output_in_standard_format(
                message=messages["EMAIL_ALREADY_VERIFIED"]
            )
            return JSONResponse(status_code=status.HTTP_200_OK, content=output_content)
        # check for verification code in UserVerificationCode table
        verification_code_response = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserVerificationCode.__tablename__,
            filters=FiltersV0(
                root={
                    UserVerificationCode.user_id.name: FilterConditionsV0(eq=user_id),
                    UserVerificationCode.user_verification_code_type.name: FilterConditionsV0(
                        eq=VerificationCodeTypeEnum.EMAIL_VERIFICATION.value
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
        )
        if len(verification_code_response["data"]["main"]) != 1:
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_VERIFICATION_CODE"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        """
        main process
        """

        # check if the latest verification code matches the provided code
        latest_verification_code_data = verification_code_response["data"]["main"][0]
        latest_verification_code_hash = latest_verification_code_data[
            UserVerificationCode.user_verification_code_hash.name
        ]
        if not bcrypt.checkpw(
            str(verification_code).encode("utf-8"),
            latest_verification_code_hash.encode("utf-8"),
        ):
            output_content = get_api_output_in_standard_format(
                message=messages["INCORRECT_VERIFICATION_CODE"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )
        # update user profile to mark email as verified
        email_verified_time = datetime.now(timezone.utc)
        global_object_square_database_helper.edit_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=UserProfile.__tablename__,
            filters=FiltersV0(
                root={UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
            ),
            data={
                UserProfile.user_profile_email_verified.name: email_verified_time.strftime(
                    "%Y-%m-%d %H:%M:%S.%f+00"
                ),
            },
            apply_filters=True,
        )
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            data={
                UserProfile.user_profile_email_verified.name: email_verified_time.isoformat(),
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
