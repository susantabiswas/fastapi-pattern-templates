from pydantic import BaseModel


class UserSchema(BaseModel):
    id: str
    fullname: str
    email: str

    class Config:
        from_attributes = True


class RefreshTokenRequest(BaseModel):
    refresh_token: str