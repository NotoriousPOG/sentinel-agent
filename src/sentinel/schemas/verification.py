"""Verification outcome. This is not a confidence score and not a generated report."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas.correlation import Contradiction, JsonScalar


class VerificationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=64)
    detail: str = Field(min_length=1, max_length=500)


class Statement(BaseModel):
    """A conclusion a caller asks the verifier to check.

    ``fact`` must name a tool-output field. ``inference`` does not.
    The model is not called to produce these.
    """

    model_config = ConfigDict(extra="forbid")

    presented_as: Literal["fact", "inference"]
    text: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(min_length=1)
    field: str | None = Field(default=None, max_length=64)
    value: JsonScalar = None


class FailedLookup(BaseModel):
    """A tool call that failed. This is not a verdict."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=64)
    query: dict[str, Any]
    reason: str = Field(min_length=1, max_length=128)


class VerificationResult(BaseModel):
    """Accept or reject a report. Contradictions are listed, not scored."""

    model_config = ConfigDict(extra="forbid")

    accepted: bool
    issues: list[VerificationIssue]
    contradictions: list[Contradiction]
