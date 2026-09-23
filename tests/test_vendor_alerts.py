"""Documented vendor alert shapes. These tests do not call a vendor API."""

import pytest
from fastapi.testclient import TestClient

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import AlertSeverity
from sentinel.services.sources import (
    CrowdStrikeFalconAdapter,
    DefenderAdapter,
    ElasticAdapter,
    SplunkAdapter,
)

_SHA = "ab" * 32


def test_crowdstrike_detection_summary_maps_documented_fields() -> None:
    alert = CrowdStrikeFalconAdapter().normalize(
        {
            "detection_id": "ldt:abc:123",
            "created_timestamp": "2026-09-22T00:00:00Z",
            "max_severity_displayname": "High",
            "max_severity": 70,
            "device": {"hostname": "lab-host"},
            "behaviors": [
                {
                    "filename": "powershell.exe",
                    "cmdline": "powershell -enc ZQ==",
                    "user_name": "alex",
                    "ioc_type": "sha256",
                    "ioc_value": _SHA,
                }
            ],
        }
    )
    assert alert.source == "crowdstrike_falcon"
    assert alert.alert_id == "ldt:abc:123"
    assert alert.severity is AlertSeverity.HIGH
    assert alert.hostname == "lab-host"
    assert alert.process == "powershell.exe"
    assert alert.command_line == "powershell -enc ZQ=="
    assert alert.username == "alex"
    assert alert.file_hash == _SHA
    assert alert.raw_event["max_severity"] == 70


def test_crowdstrike_number_severity_is_not_a_band() -> None:
    alert = CrowdStrikeFalconAdapter().normalize(
        {
            "detection_id": "ldt:abc:124",
            "created_timestamp": "2026-09-22T00:00:00Z",
            "max_severity": 70,
        }
    )
    assert alert.severity is None


def test_defender_alert_resource_maps_documented_fields() -> None:
    alert = DefenderAdapter().normalize(
        {
            "id": "da637472900382838869_1364969609",
            "title": "Low-reputation arbitrary code executed by signed executable",
            "description": "Synthetic copy of the documented title shape.",
            "severity": "Low",
            "alertCreationTime": "2021-01-26T20:33:57.7220239Z",
            "computerDnsName": "temp123.middleeast.corp.microsoft.com",
            "relatedUser": {"userName": "temp123", "domainName": "DOMAIN"},
            "mitreTechniques": ["T1064"],
        }
    )
    assert alert.source == "microsoft_defender"
    assert alert.severity is AlertSeverity.LOW
    assert alert.hostname == "temp123.middleeast.corp.microsoft.com"
    assert alert.username == "temp123"
    assert alert.raw_event["mitreTechniques"] == ["T1064"]
    assert "T1064" not in alert.model_dump(exclude={"raw_event"}).values()


def test_elastic_hit_uses_document_id_not_rule_uuid() -> None:
    alert = ElasticAdapter().normalize(
        {
            "_id": "alert-doc-1",
            "_source": {
                "@timestamp": "2026-09-22T00:00:00.000Z",
                "kibana": {
                    "alert": {
                        "severity": "high",
                        "rule": {
                            "name": "Suspicious PowerShell",
                            "description": "Documented rule description field.",
                            "uuid": "rule-uuid-should-not-be-the-alert-id",
                        },
                    }
                },
                "host": {"name": "web-1"},
                "user": {"name": "alex"},
                "source": {"ip": "203.0.113.44"},
                "destination": {"ip": "203.0.113.10"},
                "process": {"name": "powershell.exe", "command_line": "powershell -enc ZQ=="},
                "file": {"hash": {"sha256": _SHA}},
            },
        }
    )
    assert alert.alert_id == "alert-doc-1"
    assert alert.source == "elastic"
    assert alert.severity is AlertSeverity.HIGH
    assert str(alert.source_ip) == "203.0.113.44"
    assert str(alert.destination_ip) == "203.0.113.10"
    assert alert.file_hash == _SHA
    assert alert.alert_id != "rule-uuid-should-not-be-the-alert-id"


def test_splunk_notable_promotes_ip_fields_only() -> None:
    alert = SplunkAdapter().normalize(
        {
            "event_id": "notable-1",
            "rule_id": "rule-1",
            "rule_name": "Brute Force Access Behavior Detected",
            "_time": 1758499200,
            "urgency": "high",
            "src": "192.0.2.50",
            "dest": "gateway.example",
            "user": "root",
            "src_user": "correlation-author",
            "host": "search-head",
        }
    )
    assert alert.alert_id == "notable-1"
    assert alert.source == "splunk"
    assert alert.severity is AlertSeverity.HIGH
    assert str(alert.source_ip) == "192.0.2.50"
    assert alert.destination_ip is None
    assert alert.username == "root"
    assert alert.hostname is None
    assert alert.raw_event["host"] == "search-head"
    assert alert.raw_event["src_user"] == "correlation-author"


def test_splunk_unknown_urgency_fails_closed() -> None:
    with pytest.raises(AlertValidationError):
        SplunkAdapter().normalize(
            {
                "event_id": "notable-2",
                "rule_name": "Example",
                "_time": "2026-09-22T00:00:00Z",
                "urgency": "severe",
            }
        )


def test_vendor_source_is_accepted_by_the_api(client: TestClient) -> None:
    response = client.post(
        "/alerts",
        json={
            "source": "microsoft_defender",
            "payload": {
                "id": "defender-api-1",
                "title": "Documented alert title",
                "severity": "Medium",
                "alertCreationTime": "2026-09-22T00:00:00Z",
            },
        },
    )
    assert response.status_code == 201
    assert response.json()["alert"]["source"] == "microsoft_defender"
    assert response.json()["alert"]["severity"] == "medium"
