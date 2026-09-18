"""Investigation status and the persisted-shape state object.

Transitions live in ``sentinel.agents.transitions``. This module only holds data.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.schemas.timestamps import require_aware


class InvestigationStatus(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    INVESTIGATING = "INVESTIGATING"
    VERIFYING = "VERIFYING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    AWAITING_REVIEW = "AWAITING_REVIEW"


class InvestigationState(BaseModel):
    """Explicit investigation state. The executor that walks this is milestone 4."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=128)
    alert_id: str = Field(min_length=1, max_length=256)
    status: InvestigationStatus
    tool_calls_made: int = Field(ge=0)
    max_tool_calls: int = Field(ge=1)
    retries: int = Field(ge=0)
    max_retries: int = Field(ge=0)
    tokens_used: int = Field(default=0, ge=0)
    token_budget: int = Field(ge=1)
    started_at: datetime
    updated_at: datetime
    deadline_at: datetime
    error: str | None = Field(default=None, max_length=2000)
    seen_tool_calls: list[str] = Field(default_factory=list)

    @field_validator("started_at", "updated_at", "deadline_at")
    @classmethod
    def _datetimes(cls, value: datetime) -> datetime:
        return require_aware(value)


class CreateInvestigationRequest(BaseModel):
    """Body reserved for ``POST /investigations``. The route does not create one."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=256)
