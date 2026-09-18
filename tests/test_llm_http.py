"""OpenAI-compatible client. The transport is fake. No socket is opened."""

import json

import httpx2
import pytest
from pydantic import SecretStr

from sentinel.agents.decision import ModelTurn
from sentinel.config.settings import Settings
from sentinel.errors import ConfigurationError, LlmTransportError, ModelOutputInvalid
from sentinel.services.llm import LlmMessage, LlmRole
from sentinel.services.llm_http import HttpxLlmTransport, build_llm_client

KEY = "sk-test-key-do-not-leak"


class FakeTransport:
    def __init__(
        self, payload: dict[str, object] | None = None, error: Exception | None = None
    ) -> None:
        self.payload = payload if payload is not None else {}
        self.error = error
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        url: str,
        *,
        headers: object,
        body: object,
        timeout_seconds: float,
    ) -> dict[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers) if isinstance(headers, dict) else {},
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error is not None:
            raise self.error
        return self.payload


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "sqlite+pysqlite:///:memory:",
        "llm_base_url": "https://llm.example/v1",
        "llm_api_key": SecretStr(KEY),
        "llm_model": "unit-model",
        "provider_timeout_seconds": 5,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _message() -> LlmMessage:
    return LlmMessage(role=LlmRole.USER, content="investigate")


def test_missing_url_key_or_model_is_configuration_error() -> None:
    with pytest.raises(ConfigurationError) as missing:
        build_llm_client(_settings(llm_base_url=None))
    assert missing.value.provider == "llm"
    assert KEY not in str(missing.value)

    with pytest.raises(ConfigurationError):
        build_llm_client(_settings(llm_api_key=None))
    with pytest.raises(ConfigurationError):
        build_llm_client(_settings(llm_model=None))
    with pytest.raises(ConfigurationError):
        build_llm_client(_settings(llm_base_url="http://llm.example/v1"))
    with pytest.raises(ConfigurationError):
        build_llm_client(_settings(llm_base_url=f"https://user:{KEY}@llm.example/v1"))


def test_client_sends_the_key_only_as_a_header_and_validates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = {
        "action": "finish",
        "tool": None,
        "arguments": {},
    }
    transport = FakeTransport({"choices": [{"message": {"content": json.dumps(payload)}}]})
    client = build_llm_client(_settings(), transport=transport)
    with caplog.at_level("DEBUG"):
        parsed = client.complete_structured([_message()], ModelTurn)
    assert isinstance(parsed, ModelTurn)
    assert parsed.action.value == "finish"
    call = transport.calls[0]
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == f"Bearer {KEY}"
    assert KEY not in str(call["body"])
    assert call["url"] == "https://llm.example/v1/chat/completions"
    rendered = f"{caplog.text} {client!r} {client!s} {parsed!r}"
    assert KEY not in rendered


def test_schema_invalid_body_redacts_the_key() -> None:
    transport = FakeTransport({"choices": [{"message": {"content": "not-json " + KEY}}]})
    client = build_llm_client(_settings(), transport=transport)
    with pytest.raises(ModelOutputInvalid) as caught:
        client.complete_structured([_message()], ModelTurn)
    assert KEY not in caught.value.raw_text
    assert KEY not in caught.value.detail
    assert KEY not in str(caught.value)
    assert "[redacted]" in caught.value.raw_text


def test_transport_exception_does_not_carry_the_key() -> None:
    transport = FakeTransport(error=RuntimeError(f"boom {KEY}"))
    client = build_llm_client(_settings(), transport=transport)
    with pytest.raises(LlmTransportError) as caught:
        client.complete_structured([_message()], ModelTurn)
    assert caught.value.reason == "transport"
    assert caught.value.__cause__ is None
    assert KEY not in str(caught.value)
    assert KEY not in repr(caught.value)


def test_injected_transport_does_not_construct_an_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("httpx client constructed")

    monkeypatch.setattr("sentinel.services.llm_http.httpx2.Client", refuse)
    transport = FakeTransport(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({"action": "finish", "tool": None, "arguments": {}})
                    }
                }
            ]
        }
    )
    client = build_llm_client(_settings(), transport=transport)
    client.complete_structured([_message()], ModelTurn)


def test_httpx_transport_maps_timeout_without_leaking_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Client:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            self.kwargs = kwargs

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def post(self, url: str, *, headers: dict[str, str], json: object) -> object:
            assert self.kwargs["follow_redirects"] is False
            assert self.kwargs["trust_env"] is False
            raise httpx2.TimeoutException(headers["Authorization"])

    monkeypatch.setattr("sentinel.services.llm_http.httpx2.Client", _Client)
    transport = HttpxLlmTransport()
    with pytest.raises(LlmTransportError) as caught:
        transport.post_json(
            "https://llm.example/v1/chat/completions",
            headers={"Authorization": f"Bearer {KEY}"},
            body={"model": "unit-model"},
            timeout_seconds=5,
        )
    assert caught.value.reason == "timeout"
    assert caught.value.__cause__ is None
    assert KEY not in str(caught.value)
    assert KEY not in repr(caught.value)
