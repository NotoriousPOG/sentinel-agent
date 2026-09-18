"""Process configuration from ``SENTINEL_*`` environment variables.

No credential has a default. Fields reserved for later milestones are loaded
so they stay ``SecretStr`` values, but no client reads them in this release.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """Runtime settings.

    Consumed in milestone 1: ``database_url``, ``log_level``, ``demo_mode``.
    ``demo_mode`` is readable and changes nothing else. Mock providers do not
    exist yet.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite+pysqlite:///./sentinel.db"
    log_level: LogLevel = "INFO"
    demo_mode: bool = False

    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model: str | None = None

    max_tool_calls: int = Field(default=8, ge=1, le=32)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_repair_attempts: int = Field(default=1, ge=0, le=3)
    investigation_timeout_seconds: int = Field(default=120, ge=1, le=900)
    token_budget: int = Field(default=24_000, ge=1, le=200_000)

    @field_validator("database_url")
    @classmethod
    def _database_url(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("database_url must not be empty")
        if not (stripped.startswith("sqlite") or stripped.startswith("postgresql")):
            raise ValueError("database_url must be a sqlite or postgresql SQLAlchemy URL")
        return stripped

    @field_validator("llm_base_url", "llm_api_key", "llm_model", mode="before")
    @classmethod
    def _blank_optional(cls, value: object) -> object:
        if value == "":
            return None
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings. Tests clear the cache after changing the environment."""
    return Settings()
