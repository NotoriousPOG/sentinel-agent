"""Map Wazuh's documented alert JSON onto ``NormalizedAlert``.

This module does not open a socket. Fields that Wazuh documents but this
model has no place for (``full_log``, MITRE, ``srcport``, dynamic ``audit``
objects, Windows/Sysmon shapes) stay on ``raw_event``. They are not scraped
into ``command_line``, hashes, CVEs, or domains.
"""

import copy
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import AnyHttpUrl, TypeAdapter, ValidationError

from sentinel.errors import AlertValidationError, FieldIssue
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.schemas.wazuh import WazuhAlertEnvelope
from sentinel.services.validation import issues_from_validation

# Wazuh documents levels 0-15 and does not name informational/low/medium/high/critical.
# https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
# The bands below are Sentinel's, so a level-5 sshd alert (the logtest example) is low.
_HTTP_URL = TypeAdapter(AnyHttpUrl)
# The 2017 dynamic-fields example has no offset. Wazuh manager timestamps are UTC.
_LEGACY_TIMESTAMP = "%Y %b %d %H:%M:%S"


def severity_from_level(level: int) -> AlertSeverity:
    """Map a Wazuh 0-15 level onto Sentinel's severity enum."""
    if level <= 3:
        return AlertSeverity.INFORMATIONAL
    if level <= 6:
        return AlertSeverity.LOW
    if level <= 11:
        return AlertSeverity.MEDIUM
    if level <= 13:
        return AlertSeverity.HIGH
    return AlertSeverity.CRITICAL


def _parse_iso_timestamp(text: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AlertValidationError(
            (FieldIssue(code=ValidationCode.INVALID_FIELD, field="timestamp"),)
        )
    return parsed


def parse_wazuh_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 Wazuh timestamp, or the documented ``2017 Feb 07 15:57:53`` form."""
    text = value.strip()
    parsed = _parse_iso_timestamp(text)
    if parsed is not None:
        return parsed
    try:
        naive = datetime.strptime(text, _LEGACY_TIMESTAMP)
    except ValueError as exc:
        raise AlertValidationError(
            (FieldIssue(code=ValidationCode.INVALID_FIELD, field="timestamp"),)
        ) from exc
    return naive.replace(tzinfo=UTC)


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _http_url_or_none(value: str | None) -> str | None:
    """Keep an http(s) URL. Anything else stays on ``raw_event`` and is not promoted."""
    candidate = _blank_to_none(value)
    if candidate is None or len(candidate) > 2048:
        return None
    try:
        return str(_HTTP_URL.validate_python(candidate))
    except ValidationError:
        return None


def normalize_wazuh(payload: Mapping[str, Any]) -> NormalizedAlert:
    """Map one documented Wazuh alert. Missing ``rule`` or ``id`` fails closed."""
    document: dict[str, Any] = copy.deepcopy(dict(payload))
    try:
        envelope = WazuhAlertEnvelope.model_validate(document)
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc
    if envelope.id is None or not envelope.id.strip():
        raise AlertValidationError((FieldIssue(code=ValidationCode.MISSING_FIELD, field="id"),))

    data = envelope.data
    username = None
    source_ip = None
    destination_ip = None
    url = None
    if data is not None:
        username = _blank_to_none(data.srcuser) or _blank_to_none(data.dstuser)
        username = username or _blank_to_none(data.user)
        source_ip = _blank_to_none(data.srcip)
        destination_ip = _blank_to_none(data.dstip)
        url = _http_url_or_none(data.url)

    hostname = None
    process = None
    if envelope.predecoder is not None:
        hostname = _blank_to_none(envelope.predecoder.hostname)
        process = _blank_to_none(envelope.predecoder.program_name)
    if hostname is None:
        hostname = envelope.agent.name

    try:
        return NormalizedAlert.model_validate(
            {
                "alert_id": envelope.id.strip(),
                "timestamp": parse_wazuh_timestamp(envelope.timestamp),
                "source": "wazuh",
                "title": envelope.rule.description,
                "description": envelope.rule.description,
                "severity": severity_from_level(envelope.rule.level),
                "hostname": hostname,
                "username": username,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "url": url,
                "process": process,
                "raw_event": document,
            }
        )
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc
