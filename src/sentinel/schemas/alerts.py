"""Normalized security alert.

Severity values are the usual SOC scale. The product spec names the field and
does not fix the spellings; this enum is the contract other milestones import.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from sentinel.schemas.patterns import normalize_cve, normalize_domain, normalize_hash
from sentinel.schemas.timestamps import require_aware


class AlertSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedAlert(BaseModel):
    """Canonical alert. Unknown keys are rejected, not copied onto the prompt.

    Optional indicator fields stay ``None`` when the source did not provide
    them. ``raw_event`` keeps the original document for later adapters; this
    model does not fetch anything inside it.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alert_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    source: str = Field(min_length=1, max_length=128)
    title: str | None = Field(default=None, max_length=512)
    description: str | None = Field(default=None, max_length=8000)
    severity: AlertSeverity | None = None
    hostname: str | None = Field(default=None, max_length=253)
    username: str | None = Field(default=None, max_length=256)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    domain: str | None = Field(default=None, max_length=253)
    url: AnyHttpUrl | None = None
    file_hash: str | None = Field(default=None, max_length=64)
    process: str | None = Field(default=None, max_length=512)
    command_line: str | None = Field(default=None, max_length=8192)
    cve: str | None = Field(default=None, max_length=32)
    raw_event: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, value: datetime) -> datetime:
        return require_aware(value)

    @field_validator("file_hash")
    @classmethod
    def _file_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_hash(value)

    @field_validator("cve")
    @classmethod
    def _cve(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_cve(value)

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_domain(value)

    @field_validator("url")
    @classmethod
    def _url(cls, value: AnyHttpUrl | None) -> AnyHttpUrl | None:
        if value is not None and len(str(value)) > 2048:
            raise ValueError("url is longer than 2048 characters")
        return value
