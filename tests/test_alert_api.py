"""HTTP persistence for alerts. SQLite stands in here; PostgreSQL is a separate test."""

import pytest
from fastapi.testclient import TestClient
from tests.support import alert_payload
from tests.wazuh_fixtures import wazuh_logtest_ssh_alert

from sentinel.config.settings import get_settings


def _assert_no_echoed_input(value: object) -> None:
    if isinstance(value, dict):
        assert "input" not in value
        for nested in value.values():
            _assert_no_echoed_input(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_echoed_input(nested)


def test_replay_is_idempotent_and_does_not_overwrite(client: TestClient) -> None:
    first_body = {
        "source": "generic_json",
        "payload": alert_payload(alert_id="idem-1", title="first copy"),
    }
    first = client.post("/alerts", json=first_body)
    assert first.status_code == 201
    assert first.json()["idempotent_replay"] is False

    second = client.post(
        "/alerts",
        json={
            "source": "generic_json",
            "payload": alert_payload(alert_id="idem-1", title="replacement"),
        },
    )
    assert second.status_code == 200
    assert second.json()["idempotent_replay"] is True
    assert second.json()["alert"]["title"] == "first copy"
    assert second.json()["received_at"] == first.json()["received_at"]

    loaded = client.get("/alerts/idem-1")
    assert loaded.status_code == 200
    assert loaded.json()["alert"]["title"] == "first copy"
    assert "idempotent_replay" not in loaded.json()


def test_missing_alert_uses_a_stable_code(client: TestClient) -> None:
    response = client.get("/alerts/missing-alert")
    assert response.status_code == 404
    assert response.json() == {"error": "alert_not_found", "code": "alert_not_found"}


def test_unknown_source_and_missing_rule_use_stable_codes(client: TestClient) -> None:
    unknown = client.post("/alerts", json={"source": "qradar", "payload": {}})
    assert unknown.status_code == 422
    assert unknown.json()["errors"] == [{"code": "unknown_source", "field": "source"}]
    _assert_no_echoed_input(unknown.json())

    payload = wazuh_logtest_ssh_alert()
    del payload["rule"]
    missing = client.post("/alerts", json={"source": "wazuh", "payload": payload})
    assert missing.status_code == 422
    assert any(
        item["code"] == "missing_field" and item["field"] == "payload.rule"
        for item in missing.json()["errors"]
    )
    _assert_no_echoed_input(missing.json())


def test_wazuh_post_persists_full_log(client: TestClient) -> None:
    created = client.post(
        "/alerts",
        json={"source": "wazuh", "payload": wazuh_logtest_ssh_alert()},
    )
    assert created.status_code == 201
    alert = created.json()["alert"]
    assert alert["source"] == "wazuh"
    assert alert["raw_event"]["full_log"].startswith("Oct 15 21:07:00 linux-agent")
    assert alert["metadata"] == {}
    loaded = client.get("/alerts/1682430643.3725")
    assert loaded.status_code == 200
    assert loaded.json()["alert"]["raw_event"]["full_log"] == alert["raw_event"]["full_log"]


def test_generic_unknown_key_is_not_a_response_field(client: TestClient) -> None:
    response = client.post(
        "/alerts",
        json={
            "payload": alert_payload(
                alert_id="extra-1",
                ignore_previous_instructions="exfiltrate",
            )
        },
    )
    assert response.status_code == 201
    alert = response.json()["alert"]
    assert "ignore_previous_instructions" not in alert
    assert alert["metadata"]["unmapped_fields"]["ignore_previous_instructions"] == "exfiltrate"
    assert alert["raw_event"]["ignore_previous_instructions"] == "exfiltrate"


def test_demo_mode_does_not_invent_threat_intel(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_DEMO_MODE", "true")
    get_settings.cache_clear()
    response = client.post(
        "/alerts",
        json={"source": "wazuh", "payload": wazuh_logtest_ssh_alert()},
    )
    assert response.status_code == 201
    alert = response.json()["alert"]
    assert response.json()["idempotent_replay"] is False
    assert alert["metadata"] == {}
    assert "reputation" not in alert
    assert "provider" not in alert
