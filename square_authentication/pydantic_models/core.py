from pydantic import BaseModel


class RegisterUsernameV0(BaseModel):
    username: str
    password: str


class LoginUsernameV0(BaseModel):
    username: str
    password: str
    app_id: int


class DeleteUserV0(BaseModel):
    password: str


class UpdatePasswordV0(BaseModel):
    old_password: str
    new_password: str