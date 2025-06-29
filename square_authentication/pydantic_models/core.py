from enum import Enum
from typing import Optional, List

from pydantic import BaseModel


class RegisterUsernameV0(BaseModel):
    username: str
    password: str
    app_id: Optional[int] = None


class RegisterLoginGoogleV0(BaseModel):
    google_id: str
    app_id: Optional[int] = None
    assign_app_id_if_missing: bool = False


class LoginUsernameV0(BaseModel):
    username: str
    password: str
    app_id: int
    assign_app_id_if_missing: bool = False


class DeleteUserV0(BaseModel):
    password: str


class UpdatePasswordV0(BaseModel):
    old_password: str
    new_password: str
    logout_other_sessions: bool = False
    preserve_session_refresh_token: Optional[str] = None


class TokenType(Enum):
    access_token = "access_token"
    refresh_token = "refresh_token"


class LogoutAppsV0(BaseModel):
    app_ids: List[int]


class ResetPasswordAndLoginUsingBackupCodeV0(BaseModel):
    backup_code: str
    username: str
    new_password: str
    app_id: int
    logout_other_sessions: bool = False


class SendResetPasswordEmailV0(BaseModel):
    username: str


class ResetPasswordAndLoginUsingResetEmailCodeV0(BaseModel):
    reset_email_code: str
    username: str
    new_password: str
    app_id: int
    logout_other_sessions: bool = False
