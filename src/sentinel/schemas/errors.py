"""Stable API error bodies.

Codes are a contract. Messages are not, and raw input is not echoed: alert
fields are attacker-controlled.
"""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ValidationCode(StrEnum):
    MISSING_FIELD = "missing_field"
    INVALID_FIELD = "invalid_field"
    INVALID_TYPE = "invalid_type"
    UNKNOWN_SOURCE = "unknown_source"


class FieldError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ValidationCode
    field: str = Field(min_length=1, max_length=256)


class ValidationErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["validation_error"] = "validation_error"
    errors: list[FieldError]


class AlertNotFoundBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["alert_not_found"] = "alert_not_found"
    code: Literal["alert_not_found"] = "alert_not_found"


class InvestigationNotFoundBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["investigation_not_found"] = "investigation_not_found"
    code: Literal["investigation_not_found"] = "investigation_not_found"


class ReportNotFoundBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["report_not_found"] = "report_not_found"
    code: Literal["report_not_found"] = "report_not_found"


class ReviewNotAllowedBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["review_not_allowed"] = "review_not_allowed"
    code: Literal["review_not_allowed"] = "review_not_allowed"


class NotConfiguredBody(BaseModel):
    """A required setting is missing. The body names the provider, not the secret."""

    model_config = ConfigDict(extra="forbid")

    error: Literal["not_configured"] = "not_configured"
    provider: str = Field(min_length=1, max_length=64)
