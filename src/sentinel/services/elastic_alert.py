"""Map one Elastic Security alert document onto ``NormalizedAlert``.

This is not an Elasticsearch client. The payload is a Get API hit: ``_id``
plus ``_source``. Alert fields inside ``_source`` follow
https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema.
Host, user, address, process, and hash fields follow ECS names that Elastic
copies from the source event onto the alert. A missing optional field stays
unknown. ``kibana.alert.rule.uuid`` is the rule id, not the alert id, so it
is not used as ``alert_id``.
"""

import copy
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.schemas.patterns import normalize_hash
from sentinel.services.fieldmap import (
    child,
    issue,
    optional_string,
    parse_ip,
    required_object,
    required_string,
    required_timestamp,
)
from sentinel.services.validation import issues_from_validation

_SEVERITY = {
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}


def normalize_elastic(payload: Mapping[str, Any]) -> NormalizedAlert:
    document: dict[str, Any] = copy.deepcopy(dict(payload))
    alert_id = required_string(document, "_id", max_length=256)
    source = required_object(document, "_source")
    timestamp = required_timestamp(source, "@timestamp")
    rule = child(source, "kibana", "alert", "rule")
    if rule is None:
        raise issue(ValidationCode.MISSING_FIELD, "kibana.alert.rule.name")
    title = required_string(rule, "name", max_length=512)
    description = optional_string(rule, "description", max_length=8000)
    alert = child(source, "kibana", "alert")
    severity = _severity(alert)
    host = child(source, "host")
    user = child(source, "user")
    source_ip = _ip(child(source, "source"), "ip", "source.ip")
    destination_ip = _ip(child(source, "destination"), "ip", "destination.ip")
    process = child(source, "process")
    file_hash = _sha256(source)
    try:
        return NormalizedAlert.model_validate(
            {
                "alert_id": alert_id,
                "timestamp": timestamp,
                "source": "elastic",
                "title": title,
                "description": description,
                "severity": severity,
                "hostname": optional_string(host, "name", max_length=253) if host else None,
                "username": optional_string(user, "name", max_length=256) if user else None,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "process": optional_string(process, "name", max_length=512) if process else None,
                "command_line": (
                    optional_string(process, "command_line", max_length=8192) if process else None
                ),
                "file_hash": file_hash,
                "raw_event": document,
            }
        )
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc


def _severity(alert: dict[str, Any] | None) -> AlertSeverity | None:
    if alert is None:
        return None
    label = optional_string(alert, "severity", max_length=32)
    if label is None:
        return None
    mapped = _SEVERITY.get(label.casefold())
    if mapped is None:
        raise issue(ValidationCode.INVALID_FIELD, "kibana.alert.severity")
    return mapped


def _ip(node: dict[str, Any] | None, key: str, field: str) -> str | None:
    if node is None or key not in node or node[key] is None:
        return None
    return parse_ip(node[key], field)


def _sha256(source: Mapping[str, Any]) -> str | None:
    file_node = child(source, "file", "hash")
    if file_node is None:
        return None
    value = optional_string(file_node, "sha256", max_length=64)
    if value is None:
        return None
    if len(value) != 64:
        raise issue(ValidationCode.INVALID_FIELD, "file.hash.sha256")
    try:
        return normalize_hash(value)
    except ValueError as exc:
        raise issue(ValidationCode.INVALID_FIELD, "file.hash.sha256") from exc
