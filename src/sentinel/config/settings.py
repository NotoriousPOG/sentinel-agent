"""Process configuration from ``SENTINEL_*`` environment variables.

No credential has a default. Provider clients read ``SecretStr`` values only
to build a request header, and they must not copy those values into results.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """Runtime settings.

    ``demo_mode`` selects mock IP, hash, CVE, and DNS providers when a tool
    registry is built, and ``POST /investigations`` uses the in-process
    scripted demo model instead of ``OpenAiCompatibleClient``. It is not a
    fallback for a failed live lookup. MITRE still reads the checked-in
    subset. With the flag off, a missing LLM base URL, key, or model is still
    a configuration error.
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
    # Unset means data routes do not check a credential. /health and /ready never do.
    api_key: SecretStr | None = None

    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model: str | None = None

    abuseipdb_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    provider_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    provider_max_attempts: int = Field(default=3, ge=1, le=5)
    provider_backoff_seconds: float = Field(default=0.2, ge=0, le=2)

    max_tool_calls: int = Field(default=8, ge=1, le=32)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_repair_attempts: int = Field(default=1, ge=0, le=3)
    investigation_timeout_seconds: int = Field(default=120, ge=1, le=900)
    token_budget: int = Field(default=24_000, ge=1, le=200_000)

    # ``off`` attaches no exporter. ``console`` prints spans to this process.
    # There is no collector in this repository.
    otel_exporter: Literal["off", "console"] = "off"
    # Unset means estimated cost is 0. This is not a price for any model.
    usd_per_million_tokens: float | None = Field(default=None, ge=0)
    # Provider ``raw`` is not logged unless this is true, and then only at debug.
    log_provider_raw: bool = False

    @field_validator("otel_exporter", mode="before")
    @classmethod
    def _otel_exporter(cls, value: object) -> object:
        if value == "" or value is None:
            return "off"
        return value

    @field_validator("usd_per_million_tokens", mode="before")
    @classmethod
    def _price(cls, value: object) -> object:
        if value == "" or value is None:
            return None
        return value

    @field_validator("log_provider_raw", mode="before")
    @classmethod
    def _raw_flag(cls, value: object) -> object:
        if value == "" or value is None:
            return False
        return value

    @field_validator("database_url")
    @classmethod
    def _database_url(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("database_url must not be empty")
        if not (stripped.startswith("sqlite") or stripped.startswith("postgresql")):
            raise ValueError("database_url must be a sqlite or postgresql SQLAlchemy URL")
        return stripped

    @field_validator(
        "llm_base_url",
        "llm_api_key",
        "llm_model",
        "abuseipdb_api_key",
        "virustotal_api_key",
        "api_key",
        mode="before",
    )
    @classmethod
    def _blank_optional(cls, value: object) -> object:
        if value == "":
            return None
        return value


def configured_secret(value: SecretStr | None) -> str | None:
    """Return the secret text, or None when the setting is missing or blank.

    Callers must not log the return value.
    """
    if value is None:
        return None
    text = value.get_secret_value()
    if not text.strip():
        return None
    return text


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings. Tests clear the cache after changing the environment."""
    return Settings()
