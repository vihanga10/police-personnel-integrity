from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent / ".env",
        env_file_encoding="utf-8",
        env_prefix="IDENTITY_DB_",
        extra="forbid",
        hide_input_in_errors=True,
    )

    host: str = "127.0.0.1"
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = "police_identity"
    user: str = "police_identity_app"
    password: SecretStr