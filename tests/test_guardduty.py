"""GuardDuty normalization. No AWS account and no network."""

from datetime import UTC, datetime

import pytest
from examples.floci.synthetic_guardduty_finding import (
    FINDING_DOC_URL,
    synthetic_guardduty_finding,
)
from fastapi.testclient import TestClient

from sentinel.errors import AlertValidationError, NotImplementedCapability
from sentinel.schemas.alerts import AlertSeverity
from sentinel.schemas.errors import ValidationCode
from sentinel.services.guardduty import severity_from_guardduty
from sentinel.services.sources import CrowdStrikeFalconAdapter, GuardDutyAdapter


def test_fixture_cites_the_finding_api() -> None:
    assert FINDING_DOC_URL.startswith("https://docs.aws.amazon.com/guardduty/")
    description = synthetic_guardduty_finding()["description"]
    assert isinstance(description, str)
    assert FINDING_DOC_URL in description
    assert "Synthetic" in synthetic_guardduty_finding()["title"]


def test_documented_port_probe_maps_remote_ip_and_keeps_raw_event() -> None:
    payload = synthetic_guardduty_finding()
    alert = GuardDutyAdapter().normalize(payload)
    assert alert.alert_id == "synthetic-guardduty-portprobe-203-0-113-50"
    assert alert.source == "aws_guardduty"
    assert alert.timestamp == datetime(2026, 9, 19, 3, 45, tzinfo=UTC)
    assert alert.severity is AlertSeverity.LOW
    assert alert.hostname == "ip-192-0-2-10.ec2.internal"
    assert str(alert.source_ip) == "203.0.113.50"
    assert str(alert.destination_ip) == "192.0.2.10"
    assert alert.username is None
    assert alert.file_hash is None
    assert alert.command_line is None
    assert alert.metadata["type"] == "Recon:EC2/PortProbeUnprotectedPort"
    assert alert.metadata["schemaVersion"] == "2.0"
    assert alert.raw_event["resource"]["instanceDetails"]["instanceId"] == "i-synthetic00000000001"
    assert alert.raw_event["service"]["action"]["actionType"] == "PORT_PROBE"
    assert alert.hostname != "i-synthetic00000000001"
    assert str(alert.source_ip) != "198.51.100.20"


def test_extra_finding_key_stays_on_raw_event() -> None:
    payload = synthetic_guardduty_finding()
    payload["not_a_sentinel_field"] = {"kept": True}
    alert = GuardDutyAdapter().normalize(payload)
    assert alert.raw_event["not_a_sentinel_field"] == {"kept": True}
    assert "not_a_sentinel_field" not in alert.model_dump()


def test_public_ip_is_not_promoted_when_it_differs_from_the_probe() -> None:
    payload = synthetic_guardduty_finding()
    interface = payload["resource"]["instanceDetails"]["networkInterfaces"][0]
    interface["privateIpAddress"] = "192.0.2.99"
    alert = GuardDutyAdapter().normalize(payload)
    assert str(alert.destination_ip) == "192.0.2.10"
    assert (
        alert.raw_event["resource"]["instanceDetails"]["networkInterfaces"][0]["privateIpAddress"]
        == "192.0.2.99"
    )


def test_api_call_remote_ip_is_not_promoted() -> None:
    payload = synthetic_guardduty_finding()
    payload["service"]["action"] = {
        "actionType": "AWS_API_CALL",
        "awsApiCallAction": {"remoteIpDetails": {"ipAddressV4": "203.0.113.50"}},
    }
    alert = GuardDutyAdapter().normalize(payload)
    assert alert.source_ip is None
    assert alert.destination_ip is None
    assert (
        alert.raw_event["service"]["action"]["awsApiCallAction"]["remoteIpDetails"]["ipAddressV4"]
        == "203.0.113.50"
    )


def test_eventbridge_envelope_fails_closed() -> None:
    envelope = {
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "detail": synthetic_guardduty_finding(),
    }
    with pytest.raises(AlertValidationError) as caught:
        GuardDutyAdapter().normalize(envelope)
    assert caught.value.issues[0].code is ValidationCode.MISSING_FIELD
    assert caught.value.issues[0].field == "id"


def test_missing_title_is_allowed() -> None:
    payload = synthetic_guardduty_finding()
    del payload["title"]
    alert = GuardDutyAdapter().normalize(payload)
    assert alert.title is None
    assert alert.alert_id == "synthetic-guardduty-portprobe-203-0-113-50"


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "accountId",
        "arn",
        "createdAt",
        "region",
        "resource",
        "schemaVersion",
        "severity",
        "type",
        "updatedAt",
    ],
)
def test_missing_required_field_fails_closed(field: str) -> None:
    payload = synthetic_guardduty_finding()
    del payload[field]
    with pytest.raises(AlertValidationError) as caught:
        GuardDutyAdapter().normalize(payload)
    assert caught.value.issues[0].code is ValidationCode.MISSING_FIELD
    assert caught.value.issues[0].field == field


def test_blank_id_fails_closed() -> None:
    payload = synthetic_guardduty_finding()
    payload["id"] = "  "
    with pytest.raises(AlertValidationError) as caught:
        GuardDutyAdapter().normalize(payload)
    assert caught.value.issues[0].code is ValidationCode.MISSING_FIELD
    assert caught.value.issues[0].field == "id"


def test_invalid_remote_ip_fails_closed() -> None:
    payload = synthetic_guardduty_finding()
    details = payload["service"]["action"]["portProbeAction"]["portProbeDetails"][0]
    details["remoteIpDetails"]["ipAddressV4"] = "not-an-ip"
    with pytest.raises(AlertValidationError) as caught:
        GuardDutyAdapter().normalize(payload)
    assert caught.value.issues[0].code is ValidationCode.INVALID_FIELD
    assert caught.value.issues[0].field.endswith("ipAddressV4")


def test_non_object_payload_is_rejected() -> None:
    with pytest.raises(TypeError):
        GuardDutyAdapter().normalize(["not", "a", "finding"])


def test_other_vendors_still_raise() -> None:
    with pytest.raises(NotImplementedCapability, match="not scheduled"):
        CrowdStrikeFalconAdapter().normalize(synthetic_guardduty_finding())


@pytest.mark.parametrize(
    ("value", "severity"),
    [
        (1.0, AlertSeverity.LOW),
        (3.9, AlertSeverity.LOW),
        (4.0, AlertSeverity.MEDIUM),
        (6.9, AlertSeverity.MEDIUM),
        (7.0, AlertSeverity.HIGH),
        (8.9, AlertSeverity.HIGH),
        (9.0, AlertSeverity.CRITICAL),
        (10.0, AlertSeverity.CRITICAL),
    ],
)
def test_documented_severity_bands(value: float, severity: AlertSeverity) -> None:
    assert severity_from_guardduty(value) is severity
    payload = synthetic_guardduty_finding()
    payload["severity"] = value
    assert GuardDutyAdapter().normalize(payload).severity is severity


@pytest.mark.parametrize("value", [0.9, 10.1, True, "high"])
def test_severity_outside_the_documented_range_fails_closed(value: object) -> None:
    payload = synthetic_guardduty_finding()
    payload["severity"] = value
    with pytest.raises(AlertValidationError) as caught:
        GuardDutyAdapter().normalize(payload)
    assert caught.value.issues[0].field == "severity"


def test_mutating_the_input_does_not_change_raw_event() -> None:
    payload = synthetic_guardduty_finding()
    alert = GuardDutyAdapter().normalize(payload)
    payload["title"] = "changed"
    assert alert.raw_event["title"].startswith("Synthetic:")
    assert alert.raw_event is not payload


def test_post_alerts_accepts_the_finding_object(client: TestClient) -> None:
    created = client.post(
        "/alerts",
        json={"source": "aws_guardduty", "payload": synthetic_guardduty_finding()},
    )
    assert created.status_code == 201
    alert = created.json()["alert"]
    assert alert["source"] == "aws_guardduty"
    assert alert["alert_id"] == "synthetic-guardduty-portprobe-203-0-113-50"
    assert alert["raw_event"]["id"] == alert["alert_id"]
