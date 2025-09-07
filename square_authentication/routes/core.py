from typing import Annotated, List

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.params import Query
from fastapi.responses import JSONResponse
from square_commons import get_api_output_in_standard_format
from square_database_structure.square.authentication.enums import (
    RecoveryMethodEnum,
)

from square_authentication.configuration import (
    global_object_square_logger,
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
from square_authentication.utils.routes.core import (
    util_register_username_v0,
    util_register_login_google_v0,
    util_get_user_details_v0,
    util_update_user_app_ids_v0,
    util_login_username_v0,
    util_generate_access_token_v0,
    util_logout_v0,
    util_logout_apps_v0,
    util_logout_all_v0,
    util_update_username_v0,
    util_delete_user_v0,
    util_update_password_v0,
    util_validate_and_get_payload_from_token_v0,
    util_update_user_recovery_methods_v0,
    util_generate_account_backup_codes_v0,
    util_reset_password_and_login_using_backup_code_v0,
    util_send_reset_password_email_v0,
    util_reset_password_and_login_using_reset_email_code_v0,
)

router = APIRouter(
    tags=["core"],
)


@router.post("/register_username/v0")
@global_object_square_logger.auto_logger()
async def register_username_v0(
    body: RegisterUsernameV0,
):
    try:
        return util_register_username_v0(
            username=body.username,
            password=body.password,
            app_id=body.app_id,
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


@router.post("/register_login_google/v0")
async def register_login_google_v0(body: RegisterLoginGoogleV0):
    try:
        return util_register_login_google_v0(
            app_id=body.app_id,
            google_id=body.google_id,
            assign_app_id_if_missing=body.assign_app_id_if_missing,
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


@router.get("/get_user_details/v0")
@global_object_square_logger.auto_logger()
async def get_user_details_v0(
    access_token: Annotated[str, Header()],
):
    try:
        return util_get_user_details_v0(access_token=access_token)
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


@router.patch("/update_user_app_ids/v0")
@global_object_square_logger.auto_logger()
async def update_user_app_ids_v0(
    access_token: Annotated[str, Header()],
    app_ids_to_add: List[int],
    app_ids_to_remove: List[int],
):
    try:
        return util_update_user_app_ids_v0(
            access_token=access_token,
            app_ids_to_add=app_ids_to_add,
            app_ids_to_remove=app_ids_to_remove,
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


@router.post("/login_username/v0")
@global_object_square_logger.auto_logger()
async def login_username_v0(body: LoginUsernameV0):
    username = body.username
    password = body.password
    app_id = body.app_id
    assign_app_id_if_missing = body.assign_app_id_if_missing
    username = username.lower()
    try:
        return util_login_username_v0(
            username=username,
            password=password,
            app_id=app_id,
            assign_app_id_if_missing=assign_app_id_if_missing,
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


@router.get("/generate_access_token/v0")
@global_object_square_logger.auto_logger()
async def generate_access_token_v0(
    refresh_token: Annotated[str, Header()],
):
    try:
        return util_generate_access_token_v0(
            refresh_token=refresh_token,
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


@router.delete("/logout/v0")
@global_object_square_logger.auto_logger()
async def logout_v0(
    refresh_token: Annotated[str, Header()],
):
    try:
        return util_logout_v0(
            refresh_token=refresh_token,
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


@router.post("/logout/apps/v0")
@global_object_square_logger.auto_logger()
async def logout_apps_v0(
    access_token: Annotated[str, Header()],
    body: LogoutAppsV0,
):
    app_ids = body.app_ids
    try:
        return util_logout_apps_v0(access_token=access_token, app_ids=app_ids)
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


@router.delete("/logout/all/v0")
@global_object_square_logger.auto_logger()
async def logout_all_v0(
    access_token: Annotated[str, Header()],
):
    try:
        return util_logout_all_v0(access_token=access_token)
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


@router.patch("/update_username/v0")
@global_object_square_logger.auto_logger()
async def update_username_v0(
    new_username: str,
    access_token: Annotated[str, Header()],
):
    try:
        return util_update_username_v0(
            new_username=new_username, access_token=access_token
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


@router.post("/delete_user/v0")
@global_object_square_logger.auto_logger()
async def delete_user_v0(
    body: DeleteUserV0,
    access_token: Annotated[str, Header()],
):
    password = body.password
    try:
        return util_delete_user_v0(
            password=password,
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
        return util_update_password_v0(
            old_password=old_password,
            new_password=new_password,
            logout_other_sessions=logout_other_sessions,
            preserve_session_refresh_token=preserve_session_refresh_token,
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


@router.get("/validate_and_get_payload_from_token/v0")
@global_object_square_logger.auto_logger()
async def validate_and_get_payload_from_token_v0(
    app_id: int,
    token: Annotated[str, Header()],
    token_type: TokenType = Query(...),
):
    try:
        return util_validate_and_get_payload_from_token_v0(
            app_id=app_id,
            token=token,
            token_type=token_type,
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


@router.patch("/update_user_recovery_methods/v0")
@global_object_square_logger.auto_logger()
async def update_user_recovery_methods_v0(
    access_token: Annotated[str, Header()],
    recovery_methods_to_add: List[RecoveryMethodEnum] = None,
    recovery_methods_to_remove: List[RecoveryMethodEnum] = None,
):
    try:
        return util_update_user_recovery_methods_v0(
            access_token=access_token,
            recovery_methods_to_add=recovery_methods_to_add,
            recovery_methods_to_remove=recovery_methods_to_remove,
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


@router.post("/generate_account_backup_codes/v0")
@global_object_square_logger.auto_logger()
async def generate_account_backup_codes_v0(
    access_token: Annotated[str, Header()],
):
    try:
        return util_generate_account_backup_codes_v0(
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
        return util_reset_password_and_login_using_backup_code_v0(
            backup_code=backup_code,
            username=username,
            new_password=new_password,
            app_id=app_id,
            logout_other_sessions=logout_other_sessions,
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


@router.post("/send_reset_password_email/v0")
@global_object_square_logger.auto_logger()
async def send_reset_password_email_v0(
    body: SendResetPasswordEmailV0,
):
    username = body.username
    try:
        return util_send_reset_password_email_v0(
            username=username,
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
        return util_reset_password_and_login_using_reset_email_code_v0(
            reset_email_code=reset_email_code,
            username=username,
            new_password=new_password,
            app_id=app_id,
            logout_other_sessions=logout_other_sessions,
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
