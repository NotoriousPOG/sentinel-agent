"""OpenAI-compatible chat client behind ``LlmProvider``.

The OpenAI SDK is not imported. Tests pass a transport and do not open a
socket. A missing base URL, key, or model is ``ConfigurationError``. The key
is not logged and is not placed on an exception, a result, or stored text.
"""

import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, TypeVar
from urllib.parse import urlsplit

import httpx2
from pydantic import BaseModel, ValidationError

from sentinel.config.settings import Settings, configured_secret
from sentinel.errors import ConfigurationError, LlmTransportError, ModelOutputInvalid
from sentinel.services.llm import LlmMessage

ParsedT = TypeVar("ParsedT", bound=BaseModel)

# httpx2 debug logs include request headers. The API key lives in a header.
logging.getLogger("httpx2").setLevel(logging.WARNING)
logging.getLogger("httpcore2").setLevel(logging.WARNING)


class LlmHttpTransport(Protocol):
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """POST one JSON body. Implementations must set a timeout."""
        ...


class HttpxLlmTransport:
    """One POST. Redirects are not followed, so the key cannot ride to another host."""

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        if timeout_seconds <= 0:
            raise LlmTransportError("timeout")
        try:
            with httpx2.Client(
                timeout=timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.post(url, headers=dict(headers), json=dict(body))
        except httpx2.TimeoutException:
            raise LlmTransportError("timeout") from None
        except httpx2.RequestError:
            raise LlmTransportError("transport") from None
        if response.status_code != 200:
            raise LlmTransportError(_http_reason(response.status_code))
        try:
            parsed = response.json()
        except ValueError:
            raise LlmTransportError("invalid_response") from None
        if not isinstance(parsed, dict):
            raise LlmTransportError("invalid_response")
        return parsed


class OpenAiCompatibleClient:
    """``POST {base}/chat/completions`` and validate ``choices[0].message.content``."""

    def __init__(
        self,
        *,
        url: str,
        api_key: str,
        model: str,
        transport: LlmHttpTransport,
        timeout_seconds: float,
    ) -> None:
        self._url = url
        self._api_key = api_key
        self._model = model
        self._transport = transport
        self._timeout = timeout_seconds

    def complete_structured(
        self,
        messages: Sequence[LlmMessage],
        response_model: type[ParsedT],
    ) -> ParsedT:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": message.role.value, "content": message.content} for message in messages
            ],
            "response_format": {"type": "json_object"},
        }
        try:
            payload = self._transport.post_json(
                self._url,
                headers=headers,
                body=body,
                timeout_seconds=self._timeout,
            )
        except LlmTransportError:
            raise
        except Exception:
            raise LlmTransportError("transport") from None
        return _parse_completion(payload, response_model, secret=self._api_key)


def build_llm_client(
    settings: Settings,
    *,
    transport: LlmHttpTransport | None = None,
) -> OpenAiCompatibleClient:
    """Build the client. Missing URL, key, or model raises ``ConfigurationError``."""
    base_url = (settings.llm_base_url or "").strip()
    api_key = configured_secret(settings.llm_api_key)
    model = (settings.llm_model or "").strip()
    if not base_url or api_key is None or not model:
        raise ConfigurationError("llm")
    parts = urlsplit(base_url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise ConfigurationError("llm")
    return OpenAiCompatibleClient(
        url=base_url.rstrip("/") + "/chat/completions",
        api_key=api_key,
        model=model,
        transport=transport or HttpxLlmTransport(),
        timeout_seconds=settings.provider_timeout_seconds,
    )


def _parse_completion[ParsedT: BaseModel](
    payload: dict[str, Any],
    response_model: type[ParsedT],
    *,
    secret: str,
) -> ParsedT:
    content = _message_content(payload)
    redacted = content.replace(secret, "[redacted]") if secret else content
    try:
        parsed = json.loads(redacted)
    except json.JSONDecodeError:
        raise _invalid(redacted, "response did not match the required schema") from None
    if not isinstance(parsed, dict):
        raise _invalid(redacted, "response did not match the required schema")
    try:
        return response_model.model_validate(parsed)
    except ValidationError as exc:
        raise _invalid(redacted, _schema_detail(exc, secret)) from None


def _message_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return json.dumps(payload)
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return json.dumps(payload)
    content = message.get("content")
    if not isinstance(content, str):
        return json.dumps(payload)
    return content


def _schema_detail(exc: ValidationError, secret: str) -> str:
    parts: list[str] = []
    for item in exc.errors():
        location = ".".join(str(part) for part in item.get("loc", ()))
        kind = item.get("type", "invalid")
        if not isinstance(kind, str):
            kind = "invalid"
        parts.append(f"{location or 'response'}: {kind}")
    text = "; ".join(parts) if parts else "response did not match the required schema"
    if secret:
        text = text.replace(secret, "[redacted]")
    return text[:2000]


def _invalid(raw_text: str, detail: str) -> ModelOutputInvalid:
    return ModelOutputInvalid(raw_text=raw_text, detail=detail)


def _http_reason(status_code: int) -> str:
    if 100 <= status_code <= 599:
        return f"http_{status_code}"
    return "invalid_response"
