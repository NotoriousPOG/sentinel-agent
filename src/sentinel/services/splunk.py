"""Map one Splunk Enterprise Security notable event onto ``NormalizedAlert``.

This is not a Splunk search client. Fields follow the notable-event list at
https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/notableeventsplunkes/usingnotableeventsinsearch
and the Incident Management data model at
https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/datamodelsusedbyes.

``rule_name`` and ``_time`` are required. ``alert_id`` is ``event_id`` when
present, otherwise ``rule_id``. ``src`` and ``dest`` are promoted only when
they are IP addresses. ``host`` is the search head in the notable docs, so it
is not copied to ``hostname``. ``src_user`` is the correlation-search author
in those docs, so it is not copied to ``username``.
"""

import copy
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.services.fieldmap import (
    epoch_or_timestamp,
    issue,
    optional_string,
    parse_ip,
    required_string,
)
from sentinel.services.validation import issues_from_validation

# Urgency words named in the Enterprise Security incident-review docs.
_URGENCY = {
    "informational": AlertSeverity.INFORMATIONAL,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}


def normalize_splunk(payload: Mapping[str, Any]) -> NormalizedAlert:
    document: dict[str, Any] = copy.deepcopy(dict(payload))
    title = required_string(document, "rule_name", max_length=512)
    if "_time" not in document:
        raise issue(ValidationCode.MISSING_FIELD, "_time")
    timestamp = epoch_or_timestamp(document["_time"], "_time")
    alert_id = optional_string(document, "event_id", max_length=256) or optional_string(
        document, "rule_id", max_length=256
    )
    if alert_id is None:
        raise issue(ValidationCode.MISSING_FIELD, "event_id")
    description = optional_string(document, "rule_description", max_length=8000)
    username = optional_string(document, "user", max_length=256)
    try:
        return NormalizedAlert.model_validate(
            {
                "alert_id": alert_id,
                "timestamp": timestamp,
                "source": "splunk",
                "title": title,
                "description": description,
                "severity": _urgency(document),
                "username": username,
                "source_ip": _address(document, "src"),
                "destination_ip": _address(document, "dest"),
                "raw_event": document,
            }
        )
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc


def _urgency(document: Mapping[str, Any]) -> AlertSeverity | None:
    label = optional_string(document, "urgency", max_length=32)
    if label is None:
        return None
    if label.casefold() == "unknown":
        return None
    mapped = _URGENCY.get(label.casefold())
    if mapped is None:
        raise issue(ValidationCode.INVALID_FIELD, "urgency")
    return mapped


def _address(document: Mapping[str, Any], field: str) -> str | None:
    if field not in document or document[field] is None:
        return None
    value = document[field]
    if not isinstance(value, str) or not value.strip():
        raise issue(ValidationCode.INVALID_TYPE, field)
    try:
        return parse_ip(value, field)
    except AlertValidationError:
        return None
