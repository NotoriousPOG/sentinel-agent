"""Analyst decisions. Recording a decision does not run a response action."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class AnalystReview(BaseModel):
    """Approve or reject the conclusion, and optionally a remediation recommendation.

    There is no execution field. Extra keys, including ``execute``, fail validation.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=128)
    conclusion: ReviewDecision
    notes: str = Field(min_length=1, max_length=4000)
    remediation: ReviewDecision | None = None
