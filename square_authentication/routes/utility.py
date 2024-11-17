import bcrypt
from fastapi import APIRouter, status, HTTPException
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format

from square_authentication.configuration import global_object_square_logger
from square_authentication.messages import messages

router = APIRouter(
    tags=["utility"],
)


@router.get("/get_text_hash/v0")
@global_object_square_logger.async_auto_logger
async def get_text_hash_v0(plain_text: str):

    try:
        """
        validation
        """
        # pass
        """
        main process
        """
        local_str_hashed_text = bcrypt.hashpw(
            plain_text.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        """
        return value
        """
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_READ_SUCCESSFUL"],
            data={"main": local_str_hashed_text},
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=output_content,
        )
    except HTTPException as http_exception:
        global_object_square_logger.logger.error(http_exception, exc_info=True)
        """
        rollback logic
        """
        # pass
        return JSONResponse(
            status_code=http_exception.status_code, content=http_exception.detail
        )
    except Exception as e:
        global_object_square_logger.logger.error(e, exc_info=True)
        """
        rollback logic
        """
        # pass
        output_content = get_api_output_in_standard_format(
            message=messages["GENERIC_500"],
            log=str(e),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=output_content
        )
