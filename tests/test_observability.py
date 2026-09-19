"""Observability. Fakes only: no collector, no socket, no API key service."""

import json
import logging

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import SecretStr, ValidationError
from tests.test_executor import CountingIp, ManualClock, ScriptedModel, TimeoutIp, _alert, _run

from sentinel.config.settings import get_settings
from sentinel.observability.logging import log_raw_payload
from sentinel.observability.metrics import format_cost, record_investigation, snapshot
from sentinel.observability.tracing import configure_tracing, install_span_exporter, tracing_mode
from sentinel.schemas.investigation import InvestigationStatus

SECRET = "sk-sentinel-test-secret-9f3c2a"
COMMAND = "cmdline-do-not-log-9f3c2a"
USERNAME = "user-do-not-log-9f3c2a"
RAW = "raw-marker-not-instructions"


def test_exporter_defaults_to_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_OTEL_EXPORTER", raising=False)
    monkeypatch.delenv("SENTINEL_USD_PER_MILLION_TOKENS", raising=False)
    monkeypatch.delenv("SENTINEL_LOG_PROVIDER_RAW", raising=False)
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.otel_exporter == "off"
    assert settings.usd_per_million_tokens is None
    assert settings.log_provider_raw is False

    def _boom() -> None:
        raise AssertionError("console exporter was constructed")

    monkeypatch.setattr("sentinel.observability.tracing.ConsoleSpanExporter", _boom)
    configure_tracing("off")
    assert tracing_mode() == "off"


def test_blank_exporter_and_price_stay_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_OTEL_EXPORTER", "")
    monkeypatch.setenv("SENTINEL_USD_PER_MILLION_TOKENS", "")
    monkeypatch.setenv("SENTINEL_LOG_PROVIDER_RAW", "")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.otel_exporter == "off"
    assert settings.usd_per_million_tokens is None
    assert settings.log_provider_raw is False


def test_otlp_is_not_a_supported_exporter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_OTEL_EXPORTER", "otlp")
    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        get_settings()


def test_negative_price_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_USD_PER_MILLION_TOKENS", "-1")
    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        get_settings()


def test_cost_is_zero_unless_a_price_is_set() -> None:
    assert format_cost(1_000_000, None) == "0"
    assert format_cost(1_000_000, 0) == "0"
    assert format_cost(1_000_000, 2) == "2.000000"
    record_investigation("inv-cost", InvestigationStatus.FAILED.value, 1_000_000, 0)
    assert snapshot(None).estimated_cost_usd == "0"
    assert snapshot(2).estimated_cost_usd == "2.000000"


def test_console_exporter_is_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    constructed: list[str] = []

    class _Exporter:
        def __init__(self) -> None:
            constructed.append("console")

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    monkeypatch.setattr("sentinel.observability.tracing.ConsoleSpanExporter", _Exporter)
    configure_tracing("console")
    assert constructed == ["console"]
    assert tracing_mode() == "console"
    configure_tracing("off")
    assert tracing_mode() == "off"


def test_fake_investigation_hides_secret_and_command_line(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configured SecretStr and the alert command line stay out of the log."""
    monkeypatch.setenv("SENTINEL_LLM_API_KEY", SECRET)
    monkeypatch.setenv("SENTINEL_ABUSEIPDB_API_KEY", f"{SECRET}-abuse")
    monkeypatch.setenv("SENTINEL_VIRUSTOTAL_API_KEY", f"{SECRET}-vt")
    get_settings.cache_clear()
    settings = get_settings()
    assert isinstance(settings.llm_api_key, SecretStr)
    assert settings.llm_api_key.get_secret_value() == SECRET

    exporter = InMemorySpanExporter()
    install_span_exporter(exporter)
    alert = _alert(command_line=COMMAND, username=USERNAME)
    model = ScriptedModel(
        [
            {
                "action": "call_tool",
                "tool": "lookup_ip",
                "arguments": {"ip": "203.0.113.10"},
            },
            {"action": "finish", "tool": None, "arguments": {}},
        ]
    )
    clock = ManualClock(alert.timestamp)
    with caplog.at_level(logging.DEBUG):
        result = _run(model, settings=settings, alert=alert, ip=CountingIp(clock))

    rendered = caplog.text
    assert SECRET not in rendered
    assert f"{SECRET}-abuse" not in rendered
    assert f"{SECRET}-vt" not in rendered
    info = "\n".join(
        record.getMessage() for record in caplog.records if record.levelno == logging.INFO
    )
    assert COMMAND not in info
    assert USERNAME not in info
    assert RAW not in info

    events = []
    for record in caplog.records:
        if not record.name.startswith("sentinel"):
            continue
        assert SECRET not in record.getMessage()
        message = record.getMessage()
        if not message.startswith("{"):
            continue
        payload = json.loads(message)
        assert payload["correlation_id"] == result.investigation_id
        events.append(payload["event"])
    assert "investigation_started" in events
    assert "investigation_finished" in events
    assert "tool_finished" in events

    spans = [span for span in exporter.get_finished_spans() if span.name == "investigation"]
    assert len(spans) == 1
    attributes = spans[0].attributes
    assert attributes is not None
    assert attributes["correlation_id"] == result.investigation_id
    assert attributes["investigation_id"] == result.investigation_id
    rendered_span = str(dict(attributes))
    assert SECRET not in rendered_span
    assert COMMAND not in rendered_span
    assert USERNAME not in rendered_span
    assert RAW not in rendered_span
    configure_tracing("off")


def test_tool_error_is_counted(caplog: pytest.LogCaptureFixture) -> None:
    exporter = InMemorySpanExporter()
    install_span_exporter(exporter)
    model = ScriptedModel(
        [
            {
                "action": "call_tool",
                "tool": "lookup_ip",
                "arguments": {"ip": "203.0.113.10"},
            }
        ]
    )
    with caplog.at_level(logging.DEBUG):
        result = _run(model, ip=TimeoutIp())
    assert result.status is InvestigationStatus.FAILED
    current = snapshot(None)
    assert current.investigations_total == 1
    assert current.investigations_by_status[InvestigationStatus.FAILED.value] == 1
    assert current.tool_errors == 1
    assert current.tokens_total == result.tokens_used
    assert current.estimated_cost_usd == "0"
    spans = [span for span in exporter.get_finished_spans() if span.name == "investigation"]
    assert len(spans) == 1
    assert spans[0].attributes is not None
    assert spans[0].attributes["correlation_id"] == "inv-1"
    configure_tracing("off")


def test_provider_raw_is_not_logged_at_info(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "raw-debug-only-marker"
    with caplog.at_level(logging.DEBUG, logger="sentinel.providers"):
        log_raw_payload("abuseipdb", {"marker": marker})
    assert marker not in caplog.text
    info_hits = [
        record
        for record in caplog.records
        if record.levelno == logging.INFO and marker in record.getMessage()
    ]
    assert not info_hits

    monkeypatch.setenv("SENTINEL_LOG_PROVIDER_RAW", "true")
    get_settings.cache_clear()
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="sentinel.providers"):
        log_raw_payload("abuseipdb", {"marker": marker})
    debug_hits = [
        record
        for record in caplog.records
        if record.levelno == logging.DEBUG and marker in record.getMessage()
    ]
    assert debug_hits
    info_hits = [
        record
        for record in caplog.records
        if record.levelno == logging.INFO and marker in record.getMessage()
    ]
    assert not info_hits


def test_metrics_route_omits_alert_text(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_LLM_API_KEY", SECRET)
    get_settings.cache_clear()
    alert = _alert(command_line=COMMAND, username=USERNAME)
    model = ScriptedModel(
        [
            {
                "action": "call_tool",
                "tool": "lookup_ip",
                "arguments": {"ip": "203.0.113.10"},
            }
        ]
    )
    result = _run(model, alert=alert, ip=TimeoutIp(), settings=get_settings())
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "investigations_total",
        "investigations_by_status",
        "tool_errors",
        "tokens_total",
        "estimated_cost_usd",
    }
    assert body["investigations_total"] == 1
    assert body["tool_errors"] == 1
    assert body["tokens_total"] == result.tokens_used
    assert body["estimated_cost_usd"] == "0"
    assert SECRET not in response.text
    assert COMMAND not in response.text
    assert USERNAME not in response.text
    assert "not_implemented" not in response.text
