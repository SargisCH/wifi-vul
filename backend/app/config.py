from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    mikrotik_host: str = "192.168.88.1"
    mikrotik_port: int = 8728
    mikrotik_user: str = "admin"
    mikrotik_password: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
