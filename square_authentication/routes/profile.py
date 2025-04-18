import os
from typing import Annotated

from fastapi import APIRouter, HTTPException, status, Header, UploadFile
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format
from square_database_helper import FiltersV0
from square_database_helper.pydantic_models import FilterConditionsV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.tables import UserProfile

from square_authentication.configuration import (
    global_object_square_logger,
    config_str_secret_key_for_access_token,
    global_object_square_file_store_helper,
    global_object_square_database_helper,
)
from square_authentication.messages import messages
from square_authentication.utils.token import get_jwt_payload

router = APIRouter(
    tags=["profile"],
)


@router.patch("/update_profile_photo/v0")
@global_object_square_logger.auto_logger()
async def update_profile_photo_v0(
    access_token: Annotated[str, Header()],
    profile_photo: UploadFile,
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

        # validate file format
        if not profile_photo.filename.endswith((".jpg", ".jpeg", ".png")):
            output_content = get_api_output_in_standard_format(
                message=messages["INVALID_FILE_FORMAT"]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=output_content,
            )

        # validate file size
        file_size_limit_in_mib = 5
        if profile_photo.size > (file_size_limit_in_mib * 1024 * 1024):
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
        # uploading to square file store
        destination_path = f"temp/{user_id}/profile_photo/{profile_photo.filename}"
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        with open(destination_path, "wb") as out_file:
            content = await profile_photo.read()
            out_file.write(content)

        file_upload_response = (
            global_object_square_file_store_helper.upload_file_using_file_path_v0(
                file_path=destination_path,
                system_relative_path="global/users/profile_photos",
            )
        )
        os.remove(destination_path)

        # adding file storage token to user profile
        profile_update_response = global_object_square_database_helper.edit_rows_v0(
            data={
                UserProfile.user_profile_photo_storage_token.name: file_upload_response[
                    "data"
                ]["main"]
            },
            filters=FiltersV0(
                {UserProfile.user_id.name: FilterConditionsV0(eq=user_id)}
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
