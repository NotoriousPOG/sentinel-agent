"""API key gate. The key is not required unless SENTINEL_API_KEY is set."""

import logging

import pytest
from fastapi.testclient import TestClient

from sentinel.config.settings import get_settings

KEY = "sentinel-test-key-do-not-log"


def _enable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    get_settings.cache_clear()


def test_health_and_ready_stay_open_when_a_key_is_set(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable(monkeypatch)
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert KEY not in client.get("/health").text
    assert KEY not in client.get("/ready").text


def test_data_routes_reject_a_missing_or_wrong_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable(monkeypatch)
    missing = client.get("/metrics")
    assert missing.status_code == 401
    assert missing.json() == {"error": "unauthorized"}
    assert KEY not in missing.text
    wrong = client.get("/metrics", headers={"Authorization": "Bearer not-the-key"})
    assert wrong.status_code == 401
    assert "not-the-key" not in wrong.text
    posted = client.post("/alerts", json={"source": "generic_json", "payload": {}})
    assert posted.status_code == 401


def test_bearer_and_header_are_accepted(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _enable(monkeypatch)
    with caplog.at_level(logging.DEBUG):
        bearer = client.get("/metrics", headers={"Authorization": f"Bearer {KEY}"})
        header = client.get("/metrics", headers={"X-API-Key": KEY})
    assert bearer.status_code == 200
    assert header.status_code == 200
    assert KEY not in caplog.text
    assert KEY not in bearer.text


def test_openapi_names_the_credential(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    dumped = str(spec["components"])
    assert "HTTPBearer" in dumped or "bearer" in dumped.casefold()
    assert "X-API-Key" in str(spec)
    assert "/health" in spec["paths"]
    assert "security" not in spec["paths"]["/health"]["get"]
