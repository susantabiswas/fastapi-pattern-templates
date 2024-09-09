from pydantic import BaseModel


class UserSchema(BaseModel):
    id: int
    fullname: str
    email: str
    google_sub: str

    class Config:
        from_attributes = True


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AuthenticatedUserToken(BaseModel):
    access_token: str
    refresh_token: str
    user_info: UserSchema
