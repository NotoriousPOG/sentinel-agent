"""Map one Microsoft Defender for Endpoint alert onto ``NormalizedAlert``.

This is not a Defender integration. It does not call
``api.security.microsoft.com`` and it does not accept the list wrapper
``{"value": [...]}``. The object is the single-alert resource documented at
https://learn.microsoft.com/en-us/defender-endpoint/api/alerts.

``id``, ``alertCreationTime``, ``title``, and ``severity`` are required.
``computerDnsName`` and ``relatedUser.userName`` are optional. ``evidence``
and ``mitreTechniques`` stay on ``raw_event``.
"""

import copy
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.services.fieldmap import (
    child,
    issue,
    optional_string,
    required_string,
    required_timestamp,
)
from sentinel.services.validation import issues_from_validation

# The get-alert example and the create-alert property table use these words.
_SEVERITY = {
    "informational": AlertSeverity.INFORMATIONAL,
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
}


def normalize_defender(payload: Mapping[str, Any]) -> NormalizedAlert:
    document: dict[str, Any] = copy.deepcopy(dict(payload))
    alert_id = required_string(document, "id", max_length=256)
    timestamp = required_timestamp(document, "alertCreationTime")
    title = required_string(document, "title", max_length=512)
    description = optional_string(document, "description", max_length=8000)
    severity = _severity(document)
    hostname = optional_string(document, "computerDnsName", max_length=253)
    related = child(document, "relatedUser")
    username = None
    if related is not None:
        username = optional_string(related, "userName", max_length=256)
    try:
        return NormalizedAlert.model_validate(
            {
                "alert_id": alert_id,
                "timestamp": timestamp,
                "source": "microsoft_defender",
                "title": title,
                "description": description,
                "severity": severity,
                "hostname": hostname,
                "username": username,
                "raw_event": document,
            }
        )
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc


def _severity(document: Mapping[str, Any]) -> AlertSeverity:
    label = required_string(document, "severity", max_length=32)
    mapped = _SEVERITY.get(label.casefold())
    if mapped is None:
        raise issue(ValidationCode.INVALID_FIELD, "severity")
    return mapped
