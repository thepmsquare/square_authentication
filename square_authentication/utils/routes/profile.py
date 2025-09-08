from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format
from square_database_helper import FiltersV0
from square_database_helper.pydantic_models import FilterConditionsV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.tables import (
    UserProfile,
)

from square_authentication.configuration import (
    config_str_secret_key_for_access_token,
    global_object_square_database_helper,
    global_object_square_file_store_helper,
    global_object_square_logger,
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
