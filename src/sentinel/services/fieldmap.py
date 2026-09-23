"""Shared field readers for vendor alert mappers. They do not perform I/O."""

import ipaddress
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sentinel.errors import AlertValidationError, FieldIssue
from sentinel.schemas.errors import ValidationCode


def issue(code: ValidationCode, field: str) -> AlertValidationError:
    return AlertValidationError((FieldIssue(code=code, field=field),))


def required_string(payload: Mapping[str, Any], field: str, *, max_length: int) -> str:
    if field not in payload:
        raise issue(ValidationCode.MISSING_FIELD, field)
    value = _string(payload[field], field, max_length=max_length, required=True)
    if value is None:
        raise issue(ValidationCode.MISSING_FIELD, field)
    return value


def optional_string(payload: Mapping[str, Any], field: str, *, max_length: int) -> str | None:
    if field not in payload or payload[field] is None:
        return None
    return _string(payload[field], field, max_length=max_length, required=False)


def required_object(payload: Mapping[str, Any], field: str) -> dict[str, Any]:
    if field not in payload:
        raise issue(ValidationCode.MISSING_FIELD, field)
    value = payload[field]
    if not isinstance(value, dict):
        raise issue(ValidationCode.INVALID_TYPE, field)
    return value


def child(payload: Mapping[str, Any], *path: str) -> dict[str, Any] | None:
    """Walk nested objects. A missing step is None. A present non-object fails closed."""
    current: object = payload
    walked: list[str] = []
    for key in path:
        walked.append(key)
        if not isinstance(current, dict) or key not in current or current[key] is None:
            return None
        current = current[key]
        if not isinstance(current, dict):
            raise issue(ValidationCode.INVALID_TYPE, ".".join(walked))
    if not isinstance(current, dict):
        return None
    return current


def required_timestamp(payload: Mapping[str, Any], field: str) -> datetime:
    text = required_string(payload, field, max_length=64)
    return _timestamp(text, field)


def epoch_or_timestamp(value: object, field: str) -> datetime:
    """Accept an aware ISO-8601 string or a finite epoch in seconds."""
    if isinstance(value, bool):
        raise issue(ValidationCode.INVALID_TYPE, field)
    if isinstance(value, int | float):
        if value < 0 or value > 4_000_000_000:
            raise issue(ValidationCode.INVALID_FIELD, field)
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        return _timestamp(value.strip(), field)
    raise issue(ValidationCode.INVALID_TYPE, field)


def parse_ip(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise issue(ValidationCode.INVALID_TYPE, field)
    text = value.strip()
    if not text:
        raise issue(ValidationCode.INVALID_FIELD, field)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise issue(ValidationCode.INVALID_FIELD, field) from exc


def _string(value: object, field: str, *, max_length: int, required: bool) -> str | None:
    if not isinstance(value, str):
        raise issue(ValidationCode.INVALID_TYPE, field)
    stripped = value.strip()
    if not stripped:
        if required:
            raise issue(ValidationCode.MISSING_FIELD, field)
        return None
    if len(stripped) > max_length:
        raise issue(ValidationCode.INVALID_FIELD, field)
    return stripped


def _timestamp(text: str, field: str) -> datetime:
    if not text:
        raise issue(ValidationCode.MISSING_FIELD, field)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise issue(ValidationCode.INVALID_FIELD, field) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise issue(ValidationCode.INVALID_FIELD, field)
    return parsed
