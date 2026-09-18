"""Health and reserved routes."""

import pytest
from fastapi.testclient import TestClient

from sentinel import __version__
from sentinel.config.settings import get_settings


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "sentinel-agent"
    assert body["version"] == __version__
    assert body["demo_mode"] is False


def test_openapi_lists_product_routes(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    expected = {
        "/health",
        "/alerts",
        "/alerts/{id}",
        "/investigations",
        "/investigations/{id}",
        "/investigations/{id}/evidence",
        "/investigations/{id}/report",
        "/investigations/{id}/review",
        "/metrics",
    }
    assert expected <= set(paths)


def test_malformed_alert_is_rejected(client: TestClient) -> None:
    response = client.post("/alerts", json={"title": "missing required fields"})
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "validation_error"
    codes = {item["code"] for item in body["errors"]}
    assert "missing_field" in codes
    assert "input" not in response.text


def test_valid_alert_is_stored_and_reloaded(client: TestClient) -> None:
    created = client.post(
        "/alerts",
        json={
            "source": "generic_json",
            "payload": {
                "alert_id": "alert-1",
                "timestamp": "2026-09-18T12:00:00Z",
                "source": "unit-test",
            },
        },
    )
    assert created.status_code == 201
    assert created.json()["idempotent_replay"] is False
    assert created.json()["alert"]["alert_id"] == "alert-1"
    loaded = client.get("/alerts/alert-1")
    assert loaded.status_code == 200
    assert loaded.json()["alert"]["source"] == "unit-test"


def test_reserved_routes_return_501(client: TestClient) -> None:
    cases = [
        ("get", "/investigations/abc/report", None),
        ("get", "/metrics", None),
    ]
    for method, path, payload in cases:
        response = client.request(method, path, json=payload)
        assert response.status_code == 501, path
        assert response.json()["error"] == "not_implemented"


def test_investigation_lookup_is_not_a_stub(client: TestClient) -> None:
    missing_alert = client.post("/investigations", json={"alert_id": "alert-1"})
    assert missing_alert.status_code == 404
    assert missing_alert.json()["error"] == "alert_not_found"
    missing = client.get("/investigations/abc")
    assert missing.status_code == 404
    assert missing.json()["error"] == "investigation_not_found"


def test_review_execution_flag_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/investigations/inv-1/review",
        json={
            "investigation_id": "inv-1",
            "conclusion": "approve",
            "notes": "looks consistent",
            "execute": True,
        },
    )
    assert response.status_code == 422


def test_valid_review_is_not_applied(client: TestClient) -> None:
    response = client.post(
        "/investigations/inv-1/review",
        json={
            "investigation_id": "inv-1",
            "conclusion": "approve",
            "notes": "conclusion only",
            "remediation": "reject",
        },
    )
    assert response.status_code == 501
    assert response.json()["milestone"] == 6


def test_demo_mode_does_not_start_an_investigation_on_ingest(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_DEMO_MODE", "true")
    get_settings.cache_clear()
    health = client.get("/health")
    assert health.json()["demo_mode"] is True
    missing = client.post("/investigations", json={"alert_id": "alert-1"})
    assert missing.status_code == 404
    assert missing.json()["error"] == "alert_not_found"
