from typing import Annotated, Optional

from fastapi import APIRouter, Header, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format

from square_authentication.configuration import (
    global_object_square_logger,
)
from square_authentication.messages import messages
from square_authentication.pydantic_models.profile import (
    ValidateEmailVerificationCodeV0,
)
from square_authentication.utils.routes.profile import (
    util_update_profile_photo_v0,
    util_update_profile_details_v0,
    util_send_verification_email_v0,
    util_validate_email_verification_code_v0,
)

router = APIRouter(
    tags=["profile"],
)


@router.patch("/update_profile_photo/v0")
@global_object_square_logger.auto_logger()
async def update_profile_photo_v0(
    access_token: Annotated[str, Header()],
    profile_photo: Optional[UploadFile] = None,
):
    try:
        return util_update_profile_photo_v0(
            access_token=access_token,
            profile_photo=profile_photo,
        )
    except HTTPException as he:
        global_object_square_logger.logger.error(he, exc_info=True)
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"], log=str(e)
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.patch("/update_profile_details/v0")
@global_object_square_logger.auto_logger()
async def update_profile_details_v0(
    access_token: Annotated[str, Header()],
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    email: Optional[str] = None,
    phone_number_country_code: Optional[str] = None,
    phone_number: Optional[str] = None,
):
    try:
        return util_update_profile_details_v0(
            access_token=access_token,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number_country_code=phone_number_country_code,
            phone_number=phone_number,
        )
    except HTTPException as he:
        global_object_square_logger.logger.error(he, exc_info=True)
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"], log=str(e)
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.post("/send_verification_email/v0")
@global_object_square_logger.auto_logger()
async def send_verification_email_v0(
    access_token: Annotated[str, Header()],
):
    try:
        return util_send_verification_email_v0(
            access_token=access_token,
        )
    except HTTPException as he:
        global_object_square_logger.logger.error(he, exc_info=True)
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"], log=str(e)
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )


@router.post("/validate_email_verification_code/v0")
@global_object_square_logger.auto_logger()
async def validate_email_verification_code_v0(
    access_token: Annotated[str, Header()],
    body: ValidateEmailVerificationCodeV0,
):
    verification_code = body.verification_code
    try:
        return util_validate_email_verification_code_v0(
            access_token=access_token,
            verification_code=verification_code,
        )
    except HTTPException as he:
        global_object_square_logger.logger.error(he, exc_info=True)
        return JSONResponse(status_code=he.status_code, content=he.detail)
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"], log=str(e)
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )
