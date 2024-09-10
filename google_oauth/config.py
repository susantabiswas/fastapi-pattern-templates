from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    database_uri: str = "sqlite:///./test.db"
    environment: str = "dev"
    fastapi_port: int = 8000
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    JWT_SECRET_KEY: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = 600
    SESSION_SECRET_KEY: str

    @property
    def google_redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.fastapi_port}/auth/callback/google"

    class Config:
        env_file = ".env"


def get_settings() -> Settings:
    setting = Settings()
    print(f"Env: {setting.environment=} settings loaded...")
    return setting
