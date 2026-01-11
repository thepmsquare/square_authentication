from pydantic import BaseModel


class ValidateEmailVerificationCodeV0(BaseModel):
    verification_code: str


class SendVerificationEmailV0Response(BaseModel):
    expires_at: str
    cooldown_reset_at: str


class UpdateProfilePhotoV0Response(BaseModel):
    main: str | None


class UpdateProfileDetailsV0ResponseMain(BaseModel):
    user_profile_photo_storage_token: str | None
    user_profile_email: str | None
    user_profile_phone_number_country_code: str | None
    user_profile_first_name: str | None
    user_profile_last_name: str | None
    user_id: str
    user_profile_id: int
    user_profile_email_verified: str | None
    user_profile_phone_number: str | None


class UpdateProfileDetailsV0Response(BaseModel):
    main: list[UpdateProfileDetailsV0ResponseMain]
    affected_count: int


class ValidateEmailVerificationCodeV0Response(BaseModel):
    user_profile_email_verified: str
