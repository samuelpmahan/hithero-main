from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Application settings.
    """
    PROJECT_NAME: str = "Homeroom Heroes"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str
    SERVER_KEY_CAPTCHA: str
    DATABASE_SERVER: str
    DATABASE_NAME: str
    DATABASE_UID: str
    DATABASE_PASSWORD: str
    DATABASE_PORT: str
    SENDGRID_API_KEY: str

    class Config:
        env_file = ".env"

settings = Settings()