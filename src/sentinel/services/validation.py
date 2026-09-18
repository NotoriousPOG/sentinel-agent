"""Turn Pydantic errors into stable codes.

The response lists ``code`` and ``field`` only. Pydantic's ``msg`` and ``input``
can repeat attacker-controlled alert text, so they are dropped.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from sentinel.errors import FieldIssue
from sentinel.schemas.errors import ValidationCode


def code_for(error_type: str, field: str) -> ValidationCode:
    """Map one Pydantic error type onto the public code set."""
    leaf = field.rsplit(".", 1)[-1]
    if error_type == "missing":
        return ValidationCode.MISSING_FIELD
    if error_type == "literal_error" and leaf == "source":
        return ValidationCode.UNKNOWN_SOURCE
    if error_type.endswith("_type") or error_type in {
        "model_attributes_type",
        "arguments_type",
    }:
        return ValidationCode.INVALID_TYPE
    return ValidationCode.INVALID_FIELD


def issues_from_error_list(
    errors: Sequence[Mapping[str, Any]],
    *,
    drop_body: bool,
) -> tuple[FieldIssue, ...]:
    """Build field issues. ``drop_body`` strips FastAPI's leading ``body`` loc entry."""
    issues: list[FieldIssue] = []
    for error in errors:
        loc = error.get("loc", ())
        parts = [str(part) for part in loc] if isinstance(loc, tuple) else []
        if drop_body and parts and parts[0] == "body":
            parts = parts[1:]
        field = ".".join(parts) if parts else "body"
        error_type = str(error.get("type", ""))
        issues.append(FieldIssue(code=code_for(error_type, field), field=field))
    if not issues:
        issues.append(FieldIssue(code=ValidationCode.INVALID_FIELD, field="body"))
    return tuple(issues)


def issues_from_validation(exc: ValidationError) -> tuple[FieldIssue, ...]:
    """Translate a model validation error. Locations are the model's own paths."""
    return issues_from_error_list(exc.errors(), drop_body=False)
