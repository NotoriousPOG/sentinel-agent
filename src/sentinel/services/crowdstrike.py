"""Map one CrowdStrike detection summary onto ``NormalizedAlert``.

This is not a Falcon integration. It does not call the API and it does not
accept the ``{"resources": [...]}`` wrapper. The object is one item from
GetDetectSummaries, as named at
https://developer.crowdstrike.com/api-reference/collections/detects/.

``detection_id`` and ``created_timestamp`` are required. ``device.hostname``
and the first ``behaviors[]`` item are optional. Indicator fields are taken
only from documented behavior members: ``cmdline``, ``filename``, ``sha256``,
``user_name``, and ``ioc_type`` plus ``ioc_value``. ``max_severity`` as a
number is not converted into a severity band.
"""

import copy
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.schemas.patterns import normalize_domain, normalize_hash
from sentinel.services.fieldmap import (
    child,
    issue,
    optional_string,
    parse_ip,
    required_string,
    required_timestamp,
)
from sentinel.services.validation import issues_from_validation

_SEVERITY = {
    "informational": AlertSeverity.INFORMATIONAL,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}
_HASH_TYPES = {"md5": 32, "sha1": 40, "sha256": 64}


def normalize_crowdstrike(payload: Mapping[str, Any]) -> NormalizedAlert:
    document: dict[str, Any] = copy.deepcopy(dict(payload))
    alert_id = required_string(document, "detection_id", max_length=256)
    timestamp = required_timestamp(document, "created_timestamp")
    severity = _severity(document)
    device = child(document, "device")
    hostname = None
    if device is not None:
        hostname = optional_string(device, "hostname", max_length=253)
    behavior = _first_behavior(document)
    username = None
    process = None
    command_line = None
    file_hash = None
    domain = None
    source_ip = None
    if behavior is not None:
        username = optional_string(behavior, "user_name", max_length=256)
        process = optional_string(behavior, "filename", max_length=512)
        command_line = optional_string(behavior, "cmdline", max_length=8192)
        file_hash, domain, source_ip = _indicator(behavior)
        sha = optional_string(behavior, "sha256", max_length=64)
        if file_hash is None and sha is not None:
            file_hash = _hash(sha, "behaviors.sha256", length=64)
    title = optional_string(document, "max_severity_displayname", max_length=512)
    try:
        return NormalizedAlert.model_validate(
            {
                "alert_id": alert_id,
                "timestamp": timestamp,
                "source": "crowdstrike_falcon",
                "title": title,
                "description": None,
                "severity": severity,
                "hostname": hostname,
                "username": username,
                "source_ip": source_ip,
                "process": process,
                "command_line": command_line,
                "file_hash": file_hash,
                "domain": domain,
                "raw_event": document,
            }
        )
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc


def _severity(document: Mapping[str, Any]) -> AlertSeverity | None:
    label = optional_string(document, "max_severity_displayname", max_length=64)
    if label is None:
        return None
    mapped = _SEVERITY.get(label.casefold())
    if mapped is None:
        raise issue(ValidationCode.INVALID_FIELD, "max_severity_displayname")
    return mapped


def _first_behavior(document: Mapping[str, Any]) -> dict[str, Any] | None:
    if "behaviors" not in document or document["behaviors"] is None:
        return None
    behaviors = document["behaviors"]
    if not isinstance(behaviors, list):
        raise issue(ValidationCode.INVALID_TYPE, "behaviors")
    if not behaviors:
        return None
    first = behaviors[0]
    if not isinstance(first, dict):
        raise issue(ValidationCode.INVALID_TYPE, "behaviors")
    return first


def _indicator(behavior: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    kind = optional_string(behavior, "ioc_type", max_length=32)
    value = optional_string(behavior, "ioc_value", max_length=2048)
    if kind is None or value is None:
        return None, None, None
    lowered = kind.casefold()
    if lowered in _HASH_TYPES:
        return _hash(value, "behaviors.ioc_value", length=_HASH_TYPES[lowered]), None, None
    if lowered == "domain":
        try:
            return None, normalize_domain(value), None
        except ValueError as exc:
            raise issue(ValidationCode.INVALID_FIELD, "behaviors.ioc_value") from exc
    if lowered in {"ip", "ipv4", "ipv6"}:
        return None, None, parse_ip(value, "behaviors.ioc_value")
    return None, None, None


def _hash(value: str, field: str, *, length: int) -> str:
    if len(value) != length:
        raise issue(ValidationCode.INVALID_FIELD, field)
    try:
        return normalize_hash(value)
    except ValueError as exc:
        raise issue(ValidationCode.INVALID_FIELD, field) from exc
