"""Evidence records. A record is a tool result, not a sentence the model wrote."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.schemas.timestamps import require_aware


class EvidenceReliability(StrEnum):
    """Assigned by tool policy in milestone 3, never by the model."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=64)
    query: dict[str, Any]
    result: dict[str, Any]
    timestamp: datetime
    reliability: EvidenceReliability
    supports: list[str] = Field(
        default_factory=list,
        description="Claim ids this record supports. Correlation assigns these, not the model.",
    )
    contradicts: list[str] = Field(
        default_factory=list,
        description="Claim ids this record contradicts. The contradicting row is kept.",
    )

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, value: datetime) -> datetime:
        return require_aware(value)
