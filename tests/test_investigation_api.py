"""Investigation HTTP API. SQLite, a fake model, and a fake registry. No live model."""

import json
from collections.abc import Sequence
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.support import alert_payload

from sentinel.config.settings import Settings, get_settings
from sentinel.services.clock import SystemClock
from sentinel.services.llm import LlmMessage
from sentinel.storage.session import make_engine
from sentinel.tools.registry import build_registry


class ExplodingTransport:
    def request(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("tool transport was called")


class ExplodingResolver:
    def resolve(self, domain: str, *, timeout_seconds: float) -> list[str]:
        raise AssertionError("resolver was called")


class ScriptedModel:
    def __init__(self, steps: list[object]) -> None:
        self._steps = list(steps)
        self.calls = 0

    def complete_structured(self, messages: Sequence[LlmMessage], response_model: type[Any]) -> Any:
        self.calls += 1
        step = self._steps.pop(0)
        return response_model.model_validate(step)


def _store_alert(client: TestClient, alert_id: str = "alert-1") -> None:
    created = client.post(
        "/alerts",
        json={"source": "generic_json", "payload": alert_payload(alert_id=alert_id)},
    )
    assert created.status_code == 201


def _patch_ports(monkeypatch: pytest.MonkeyPatch, model: ScriptedModel) -> None:
    clock = SystemClock()
    registry = build_registry(
        Settings(database_url="sqlite+pysqlite:///:memory:", demo_mode=True),
        transport=ExplodingTransport(),  # type: ignore[arg-type]
        clock=clock,
        resolver=ExplodingResolver(),
    )

    def _llm(_settings: Settings) -> ScriptedModel:
        return model

    def _tools(_settings: Settings) -> object:
        return registry

    monkeypatch.setattr("sentinel.api.routes.investigations.build_llm_client", _llm)
    monkeypatch.setattr("sentinel.api.routes.investigations.build_registry", _tools)


def _count() -> int:
    engine = make_engine(get_settings().database_url)
    try:
        with engine.connect() as connection:
            value = connection.execute(text("SELECT COUNT(*) FROM investigations")).scalar_one()
    finally:
        engine.dispose()
    return int(value)


def test_post_runs_and_get_reloads(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _store_alert(client)
    model = ScriptedModel(
        [
            {
                "action": "call_tool",
                "tool": "lookup_ip",
                "arguments": {"ip": "203.0.113.10"},
            },
            {
                "action": "call_tool",
                "tool": "lookup_ip",
                "arguments": {"ip": "203.0.113.11"},
            },
            {"action": "finish", "tool": None, "arguments": {}},
        ]
    )
    _patch_ports(monkeypatch, model)
    created = client.post("/investigations", json={"alert_id": "alert-1"})
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "VERIFYING"
    assert body["status"] not in {"COMPLETE", "AWAITING_REVIEW"}
    assert body["alert_id"] == "alert-1"
    assert body["tool_calls_made"] == 2
    assert len(body["evidence"]) == 2
    assert body["evidence"][0]["evidence_id"] != body["evidence"][1]["evidence_id"]
    assert {item["source"] for item in body["evidence"]} == {"mock:abuseipdb"}
    assert "classification" not in body
    assert "executive_summary" not in body
    investigation_id = body["investigation_id"]

    loaded = client.get(f"/investigations/{investigation_id}")
    assert loaded.status_code == 200
    assert loaded.json()["status"] == "VERIFYING"
    assert loaded.json()["tool_calls_made"] == 2
    assert loaded.json()["max_tool_calls"] == body["max_tool_calls"]
    assert loaded.json()["token_budget"] == body["token_budget"]

    evidence = client.get(f"/investigations/{investigation_id}/evidence")
    assert evidence.status_code == 200
    assert evidence.json()["investigation_id"] == investigation_id
    assert evidence.json()["evidence"] == body["evidence"]
    assert "correlated" not in evidence.text

    report = client.get(f"/investigations/{investigation_id}/report")
    assert report.status_code == 501
    assert report.json()["milestone"] == 6

    review = client.post(
        f"/investigations/{investigation_id}/review",
        json={
            "investigation_id": investigation_id,
            "conclusion": "approve",
            "notes": "not stored",
        },
    )
    assert review.status_code == 501
    assert review.json()["milestone"] == 6
    assert client.get(f"/investigations/{investigation_id}").json()["status"] == "VERIFYING"


def test_schema_failure_is_persisted_without_a_report(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_alert(client, "alert-bad")

    class _Invalid:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(
            self, messages: Sequence[LlmMessage], response_model: type[Any]
        ) -> Any:
            self.calls += 1
            from sentinel.errors import ModelOutputInvalid

            raise ModelOutputInvalid(raw_text="not-json", detail="schema_mismatch_token")

    model = _Invalid()
    monkeypatch.setenv("SENTINEL_MAX_REPAIR_ATTEMPTS", "1")
    get_settings.cache_clear()
    _patch_ports(monkeypatch, model)  # type: ignore[arg-type]
    created = client.post("/investigations", json={"alert_id": "alert-bad"})
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "FAILED"
    assert body["error"] == "model output failed schema validation"
    assert "IncidentReport" not in json.dumps(body)
    assert "classification" not in body
    assert model.calls == 2
    loaded = client.get(f"/investigations/{body['investigation_id']}")
    assert loaded.status_code == 200
    assert loaded.json()["status"] == "FAILED"
    assert loaded.json()["model_outputs"][0]["raw_text"] == "not-json"


def test_missing_alert_and_missing_investigation(client: TestClient) -> None:
    missing_alert = client.post("/investigations", json={"alert_id": "missing"})
    assert missing_alert.status_code == 404
    assert missing_alert.json() == {"error": "alert_not_found", "code": "alert_not_found"}

    missing = client.get("/investigations/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"] == "investigation_not_found"
    evidence = client.get("/investigations/does-not-exist/evidence")
    assert evidence.status_code == 404
    assert evidence.json()["code"] == "investigation_not_found"


def test_missing_llm_config_stores_nothing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_alert(client, "alert-nollm")
    monkeypatch.delenv("SENTINEL_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("SENTINEL_LLM_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_LLM_MODEL", raising=False)
    get_settings.cache_clear()
    response = client.post("/investigations", json={"alert_id": "alert-nollm"})
    assert response.status_code == 503
    assert response.json() == {"error": "not_configured", "provider": "llm"}
    assert "sk-" not in response.text
    assert _count() == 0
