from fastapi import APIRouter, status, HTTPException
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format

from square_authentication.configuration import global_object_square_logger
from square_authentication.messages import messages
from square_authentication.utils.routes.utility import util_get_text_hash_v0

router = APIRouter(
    tags=["utility"],
)


@router.get("/get_text_hash/v0")
@global_object_square_logger.auto_logger()
async def get_text_hash_v0(plain_text: str):
    try:
        return util_get_text_hash_v0(
            plain_text=plain_text,
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
