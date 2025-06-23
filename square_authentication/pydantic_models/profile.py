from pydantic import BaseModel


class ValidateEmailVerificationCodeV0(BaseModel):
    verification_code: str
