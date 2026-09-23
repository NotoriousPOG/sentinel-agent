"""Wazuh normalization against documented alert JSON. No manager is contacted."""

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.wazuh_fixtures import wazuh_auditd_dynamic_fields_alert, wazuh_logtest_ssh_alert

from sentinel.errors import AlertValidationError
from sentinel.schemas.alerts import AlertSeverity, NormalizedAlert
from sentinel.schemas.errors import ValidationCode
from sentinel.services.sources import WazuhAdapter
from sentinel.services.wazuh import parse_wazuh_timestamp

_FULL_LOG = (
    "Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928"
)


def test_documented_sshd_alert_normalizes() -> None:
    payload = wazuh_logtest_ssh_alert()
    alert = WazuhAdapter().normalize(payload)
    assert alert.alert_id == "1682430643.3725"
    assert alert.source == "wazuh"
    assert alert.severity is AlertSeverity.LOW
    assert alert.title == "sshd: Attempt to login using a non-existent user"
    assert alert.hostname == "linux-agent"
    assert alert.username == "blimey"
    assert str(alert.source_ip) == "18.18.18.18"
    assert alert.destination_ip is None
    assert alert.process == "sshd"
    assert alert.command_line is None
    assert alert.file_hash is None
    assert alert.cve is None
    assert alert.domain is None
    assert alert.url is None
    assert alert.raw_event["full_log"] == _FULL_LOG
    assert alert.raw_event["data"]["srcport"] == "48928"
    assert alert.raw_event["rule"]["mitre"]["id"] == ["T1110.001", "T1021.004", "T1078"]
    assert "srcport" not in alert.model_dump()
    assert "mitre" not in alert.model_dump()
    assert set(alert.model_dump()) <= set(NormalizedAlert.model_fields)


def test_missing_rule_fails_closed() -> None:
    payload = wazuh_logtest_ssh_alert()
    del payload["rule"]
    with pytest.raises(AlertValidationError) as caught:
        WazuhAdapter().normalize(payload)
    assert any(
        issue.code is ValidationCode.MISSING_FIELD and issue.field == "rule"
        for issue in caught.value.issues
    )


def test_documented_auditd_alert_does_not_invent_an_id() -> None:
    """The 2017 JSON example has no top-level id. Do not synthesize one."""
    with pytest.raises(AlertValidationError) as caught:
        WazuhAdapter().normalize(wazuh_auditd_dynamic_fields_alert())
    assert caught.value.issues[0].code is ValidationCode.MISSING_FIELD
    assert caught.value.issues[0].field == "id"


def test_numeric_rule_id_from_the_2017_example_is_accepted_on_a_complete_alert() -> None:
    payload = wazuh_logtest_ssh_alert()
    payload["rule"]["id"] = 5710
    alert = WazuhAdapter().normalize(payload)
    assert alert.alert_id == "1682430643.3725"


def test_documented_legacy_timestamp_is_utc() -> None:
    # Offset-less form from the dynamic-fields JSON example. Manager time is UTC.
    parsed = parse_wazuh_timestamp("2017 Feb 07 15:57:53")
    assert parsed == datetime(2017, 2, 7, 15, 57, 53, tzinfo=UTC)


def test_invalid_source_ip_fails_closed() -> None:
    payload = wazuh_logtest_ssh_alert()
    payload["data"]["srcip"] = "not-an-ip"
    with pytest.raises(AlertValidationError) as caught:
        WazuhAdapter().normalize(payload)
    assert any(issue.code is ValidationCode.INVALID_FIELD for issue in caught.value.issues)


def test_non_http_data_url_is_not_promoted() -> None:
    payload = wazuh_logtest_ssh_alert()
    payload["data"]["url"] = "javascript:alert(1)"
    alert = WazuhAdapter().normalize(payload)
    assert alert.url is None
    assert alert.raw_event["data"]["url"] == "javascript:alert(1)"


def test_http_data_url_is_promoted() -> None:
    payload = wazuh_logtest_ssh_alert()
    payload["data"]["url"] = "https://example.com/login"
    alert = WazuhAdapter().normalize(payload)
    assert str(alert.url) == "https://example.com/login"


def test_unknown_agent_address_is_not_the_source_ip() -> None:
    payload = wazuh_logtest_ssh_alert()
    payload["agent"]["ip"] = "203.0.113.50"
    alert = WazuhAdapter().normalize(payload)
    assert str(alert.source_ip) == "18.18.18.18"
    assert alert.raw_event["agent"]["ip"] == "203.0.113.50"


def test_full_log_is_not_copied_into_command_line() -> None:
    alert = WazuhAdapter().normalize(wazuh_logtest_ssh_alert())
    assert alert.command_line is None
    assert _FULL_LOG not in (alert.command_line or "")


def test_adapter_rejects_a_non_object() -> None:
    with pytest.raises(TypeError):
        WazuhAdapter().normalize(["not", "an", "object"])


def test_dynamic_sibling_object_stays_on_raw_event_when_id_is_present() -> None:
    # The documented JSON has no top-level id. This copy adds one so the
    # assertion is about the sibling ``audit`` object, not the missing-id failure.
    payload = wazuh_auditd_dynamic_fields_alert()
    payload["id"] = "1486483073.60589"
    alert = WazuhAdapter().normalize(payload)
    assert alert.severity is AlertSeverity.INFORMATIONAL
    assert alert.raw_event["audit"]["key"] == "audit"
    assert alert.command_line is None
    assert alert.file_hash is None


def test_hostname_falls_back_to_agent_name() -> None:
    payload = wazuh_logtest_ssh_alert()
    del payload["predecoder"]
    alert = WazuhAdapter().normalize(payload)
    assert alert.hostname == "centos7"
    assert alert.process is None


def test_copying_the_fixture_does_not_mutate_the_file_copy() -> None:
    first = wazuh_logtest_ssh_alert()
    second = wazuh_logtest_ssh_alert()
    first["rule"]["description"] = "changed"
    assert second["rule"]["description"] != "changed"
    assert copy.deepcopy(first)["id"] == "1682430643.3725"


def test_splunk_adapter_rejects_a_wazuh_document() -> None:
    from sentinel.services.sources import SplunkAdapter

    with pytest.raises(AlertValidationError):
        SplunkAdapter().normalize(wazuh_logtest_ssh_alert())


def test_synthetic_wazuh_example_normalizes_documentation_address() -> None:
    path = Path(__file__).resolve().parents[1] / "examples" / "wazuh-synthetic-alert.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["source"] == "wazuh"
    alert = WazuhAdapter().normalize(body["payload"])
    assert alert.alert_id == "demo-wazuh-192-0-2-50"
    assert str(alert.source_ip) == "192.0.2.50"
    assert alert.process == "sshd"
    assert "password guessing" in (alert.title or "").casefold()
    assert alert.raw_event["full_log"].startswith("Sep 22")
    assert "18.18.18.18" not in alert.raw_event["full_log"]
