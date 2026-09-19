"""Map one documented GuardDuty finding object onto ``NormalizedAlert``.

This is not a GuardDuty integration. It does not call AWS, does not list
detectors, and does not accept an EventBridge envelope. Other action shapes
stay on ``raw_event``. CrowdStrike, Defender, Elastic, and Splunk are not
implemented here.

The payload is the GetFindings ``Finding`` object (camelCase), not the
``{"Findings": [...]}`` wrapper. Required members are the ones the Finding
API marks required. A missing or mistyped required member fails closed.
This module does not invent an ``alert_id``.

https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Finding.html
https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html

Severity bands are Sentinel's reading of the documented inclusive ranges.
The page writes those endpoints to one decimal place, so the comparison
uses that precision.

https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html

The only addresses promoted to indicator fields are
``service.action.portProbeAction.portProbeDetails[].remoteIpDetails``
(source) and the matching ``localIpDetails`` (destination). Those members
are documented on PortProbeDetail. A port probe's remote address is the
probing side. Other actions, including ``awsApiCallAction.remoteIpDetails``,
are not mapped.
"""

import copy
import ipaddress
import math
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from sentinel.errors import AlertValidationError, FieldIssue
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.services.validation import issues_from_validation

# Finding.type length constraint from the Finding API.
_TYPE_MAX = 100
_ALERT_ID_MAX = 256
_HOSTNAME_MAX = 253

_PORT_PROBE = "service.action.portProbeAction.portProbeDetails"


def severity_from_guardduty(value: float) -> AlertSeverity:
    """Map a GuardDuty severity number onto Sentinel's enum.

    Documented ranges: low 1.0–3.9, medium 4.0–6.9, high 7.0–8.9,
    critical 9.0–10.0. Values outside that set fail closed. Sentinel's
    ``informational`` band is not used; GuardDuty does not define it.
    """
    if not math.isfinite(value):
        raise AlertValidationError(
            (FieldIssue(code=ValidationCode.INVALID_FIELD, field="severity"),)
        )
    tenths = round(value * 10)
    if 10 <= tenths <= 39:
        return AlertSeverity.LOW
    if 40 <= tenths <= 69:
        return AlertSeverity.MEDIUM
    if 70 <= tenths <= 89:
        return AlertSeverity.HIGH
    if 90 <= tenths <= 100:
        return AlertSeverity.CRITICAL
    raise AlertValidationError((FieldIssue(code=ValidationCode.INVALID_FIELD, field="severity"),))


def _issue(code: ValidationCode, field: str) -> AlertValidationError:
    return AlertValidationError((FieldIssue(code=code, field=field),))


def _required_string(
    payload: Mapping[str, Any], field: str, *, max_length: int | None = None
) -> str:
    if field not in payload:
        raise _issue(ValidationCode.MISSING_FIELD, field)
    value = payload[field]
    if not isinstance(value, str):
        raise _issue(ValidationCode.INVALID_TYPE, field)
    stripped = value.strip()
    if not stripped:
        raise _issue(ValidationCode.MISSING_FIELD, field)
    if max_length is not None and len(stripped) > max_length:
        raise _issue(ValidationCode.INVALID_FIELD, field)
    return stripped


def _optional_string(payload: Mapping[str, Any], field: str, *, max_length: int) -> str | None:
    if field not in payload or payload[field] is None:
        return None
    value = payload[field]
    if not isinstance(value, str):
        raise _issue(ValidationCode.INVALID_TYPE, field)
    stripped = value.strip()
    if not stripped:
        return None
    if len(stripped) > max_length:
        raise _issue(ValidationCode.INVALID_FIELD, field)
    return stripped


def _required_object(payload: Mapping[str, Any], field: str) -> dict[str, Any]:
    if field not in payload:
        raise _issue(ValidationCode.MISSING_FIELD, field)
    value = payload[field]
    if not isinstance(value, dict):
        raise _issue(ValidationCode.INVALID_TYPE, field)
    return value


def _optional_object(payload: Mapping[str, Any], field: str) -> dict[str, Any] | None:
    if field not in payload or payload[field] is None:
        return None
    value = payload[field]
    if not isinstance(value, dict):
        raise _issue(ValidationCode.INVALID_TYPE, field)
    return value


def _required_timestamp(payload: Mapping[str, Any], field: str) -> datetime:
    text = _required_string(payload, field)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise _issue(ValidationCode.INVALID_FIELD, field) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _issue(ValidationCode.INVALID_FIELD, field)
    return parsed


def _required_severity(payload: Mapping[str, Any]) -> AlertSeverity:
    if "severity" not in payload:
        raise _issue(ValidationCode.MISSING_FIELD, "severity")
    value = payload["severity"]
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _issue(ValidationCode.INVALID_TYPE, "severity")
    return severity_from_guardduty(float(value))


def _parse_ip(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise _issue(ValidationCode.INVALID_TYPE, field)
    text = value.strip()
    if not text:
        raise _issue(ValidationCode.INVALID_FIELD, field)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise _issue(ValidationCode.INVALID_FIELD, field) from exc


def _address(details: Mapping[str, Any], prefix: str) -> str | None:
    if "ipAddressV4" in details and details["ipAddressV4"] is not None:
        return _parse_ip(details["ipAddressV4"], f"{prefix}.ipAddressV4")
    if "ipAddressV6" in details and details["ipAddressV6"] is not None:
        return _parse_ip(details["ipAddressV6"], f"{prefix}.ipAddressV6")
    return None


def _ip_details(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _issue(ValidationCode.INVALID_TYPE, field)
    return _address(value, field)


def _port_probe_ips(service: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    """Return the first port-probe remote and local addresses, if that action exists."""
    if service is None:
        return None, None
    action = _optional_object(service, "action")
    if action is None:
        return None, None
    probe = _optional_object(action, "portProbeAction")
    if probe is None:
        return None, None
    if "portProbeDetails" not in probe or probe["portProbeDetails"] is None:
        return None, None
    details = probe["portProbeDetails"]
    if not isinstance(details, list):
        raise _issue(ValidationCode.INVALID_TYPE, _PORT_PROBE)
    for index, item in enumerate(details):
        prefix = f"{_PORT_PROBE}.{index}"
        if not isinstance(item, dict):
            raise _issue(ValidationCode.INVALID_TYPE, prefix)
        remote = _ip_details(item.get("remoteIpDetails"), f"{prefix}.remoteIpDetails")
        local = _ip_details(item.get("localIpDetails"), f"{prefix}.localIpDetails")
        if remote is not None or local is not None:
            return remote, local
    return None, None


def _hostname(resource: Mapping[str, Any]) -> str | None:
    details = _optional_object(resource, "instanceDetails")
    if details is None:
        return None
    if "networkInterfaces" not in details or details["networkInterfaces"] is None:
        return None
    interfaces = details["networkInterfaces"]
    if not isinstance(interfaces, list):
        raise _issue(ValidationCode.INVALID_TYPE, "resource.instanceDetails.networkInterfaces")
    for index, item in enumerate(interfaces):
        field = f"resource.instanceDetails.networkInterfaces.{index}.privateDnsName"
        if not isinstance(item, dict):
            raise _issue(
                ValidationCode.INVALID_TYPE,
                f"resource.instanceDetails.networkInterfaces.{index}",
            )
        if "privateDnsName" not in item or item["privateDnsName"] is None:
            continue
        name = item["privateDnsName"]
        if not isinstance(name, str):
            raise _issue(ValidationCode.INVALID_TYPE, field)
        stripped = name.strip()
        if not stripped:
            continue
        if len(stripped) > _HOSTNAME_MAX:
            raise _issue(ValidationCode.INVALID_FIELD, field)
        return stripped
    return None


def _check_service_name(service: Mapping[str, Any] | None) -> None:
    if service is None or "serviceName" not in service or service["serviceName"] is None:
        return
    name = service["serviceName"]
    if not isinstance(name, str):
        raise _issue(ValidationCode.INVALID_TYPE, "service.serviceName")
    # The get-findings example uses this value.
    # https://docs.aws.amazon.com/cli/latest/reference/guardduty/get-findings.html
    if name != "guardduty":
        raise _issue(ValidationCode.INVALID_FIELD, "service.serviceName")


def normalize_guardduty(payload: Mapping[str, Any]) -> NormalizedAlert:
    """Map one finding. Missing required Finding members fail closed."""
    document: dict[str, Any] = copy.deepcopy(dict(payload))
    alert_id = _required_string(document, "id", max_length=_ALERT_ID_MAX)
    created_at = _required_timestamp(document, "createdAt")
    _required_timestamp(document, "updatedAt")
    finding_type = _required_string(document, "type", max_length=_TYPE_MAX)
    account_id = _required_string(document, "accountId")
    region = _required_string(document, "region")
    arn = _required_string(document, "arn")
    schema_version = _required_string(document, "schemaVersion")
    severity = _required_severity(document)
    resource = _required_object(document, "resource")
    service = _optional_object(document, "service")
    _check_service_name(service)
    source_ip, destination_ip = _port_probe_ips(service)
    title = _optional_string(document, "title", max_length=512)
    description = _optional_string(document, "description", max_length=8000)

    try:
        return NormalizedAlert.model_validate(
            {
                "alert_id": alert_id,
                "timestamp": created_at,
                "source": "aws_guardduty",
                "title": title,
                "description": description,
                "severity": severity,
                "hostname": _hostname(resource),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "raw_event": document,
                "metadata": {
                    "accountId": account_id,
                    "region": region,
                    "type": finding_type,
                    "schemaVersion": schema_version,
                    "arn": arn,
                },
            }
        )
    except ValidationError as exc:
        raise AlertValidationError(issues_from_validation(exc)) from exc
