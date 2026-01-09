from pydantic import BaseModel


class ValidateEmailVerificationCodeV0(BaseModel):
    verification_code: str


class SendVerificationEmailV0Response(BaseModel):
    expires_at: str
    cooldown_reset_at: str
