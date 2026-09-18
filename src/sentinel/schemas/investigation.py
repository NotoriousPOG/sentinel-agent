"""Investigation status and the persisted-shape state object.

Transitions live in ``sentinel.agents.transitions``. This module only holds data.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.schemas.correlation import Contradiction, LinkedIndicator
from sentinel.schemas.evidence import Evidence
from sentinel.schemas.reports import IncidentReport
from sentinel.schemas.review import AnalystReview
from sentinel.schemas.timestamps import require_aware
from sentinel.schemas.verification import VerificationResult


class InvestigationStatus(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    INVESTIGATING = "INVESTIGATING"
    VERIFYING = "VERIFYING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    AWAITING_REVIEW = "AWAITING_REVIEW"


class ToolHistoryEntry(BaseModel):
    """One registry call recorded on the investigation. Not a second cache."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any]
    from_cache: bool
    evidence_id: str = Field(min_length=1, max_length=128)


class ModelOutputRecord(BaseModel):
    """Raw model text stored as data. It is not replayed as a system instruction."""

    model_config = ConfigDict(extra="forbid")

    raw_text: str = Field(min_length=1, max_length=20_000)
    error: str = Field(min_length=1, max_length=2000)


class InvestigationState(BaseModel):
    """Explicit investigation state. ``agents.executor`` is what walks it."""

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
    evidence: list[Evidence] = Field(default_factory=list)
    tool_history: list[ToolHistoryEntry] = Field(default_factory=list)
    model_outputs: list[ModelOutputRecord] = Field(default_factory=list)
    repair_attempts: int = Field(default=0, ge=0)
    verification: VerificationResult | None = Field(
        default=None,
        description="Set by apply_verification or report generation.",
    )
    report: IncidentReport | None = Field(
        default=None,
        description="Set only after verify_report accepts. Absent means no verified report.",
    )
    review: AnalystReview | None = Field(
        default=None,
        description="Analyst decision. Storing it does not run a response action.",
    )

    @field_validator("started_at", "updated_at", "deadline_at")
    @classmethod
    def _datetimes(cls, value: datetime) -> datetime:
        return require_aware(value)


class CreateInvestigationRequest(BaseModel):
    """Body for ``POST /investigations``. The alert must already be stored."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=256)


class EvidenceList(BaseModel):
    """Separate evidence rows for one investigation, plus links between them.

    ``indicators`` point at rows. They do not contain a merged provider result.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=128)
    evidence: list[Evidence]
    indicators: list[LinkedIndicator] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
