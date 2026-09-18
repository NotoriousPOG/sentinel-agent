"""Contracts that keep secrets and untrusted fields from drifting.

These are not a prompt-injection detector. Milestone 7 adds that.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from sentinel.config.settings import Settings, get_settings
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.security.untrusted import PLATFORM_ALERT_FIELDS, UNTRUSTED_ALERT_FIELDS


def test_untrusted_registry_matches_alert_fields() -> None:
    fields = set(NormalizedAlert.model_fields)
    assert UNTRUSTED_ALERT_FIELDS.isdisjoint(PLATFORM_ALERT_FIELDS)
    assert fields == UNTRUSTED_ALERT_FIELDS | PLATFORM_ALERT_FIELDS


def test_api_key_is_not_in_repr() -> None:
    settings = Settings(llm_api_key=SecretStr("super-secret-value"))
    rendered = f"{settings!r} {settings!s}"
    assert "super-secret-value" not in rendered


def test_health_does_not_echo_secrets(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "SENTINEL_DATABASE_URL",
        "postgresql+psycopg://user:super-secret-db@localhost:5432/sentinel",
    )
    monkeypatch.setenv("SENTINEL_LLM_API_KEY", "sk-live-secret")
    get_settings.cache_clear()
    body = client.get("/health").text
    assert "super-secret-db" not in body
    assert "sk-live-secret" not in body


def test_settings_read_budget_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_MAX_TOOL_CALLS", "3")
    monkeypatch.setenv("SENTINEL_DEMO_MODE", "false")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.max_tool_calls == 3
    assert settings.demo_mode is False
    assert settings.llm_api_key is None
