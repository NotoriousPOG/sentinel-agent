"""Shared request handling for vendor clients. No verdicts are invented here."""

import logging
from collections.abc import Mapping
from typing import Any

from pydantic import SecretStr

from sentinel.config.settings import configured_secret
from sentinel.errors import ConfigurationError, ProviderError
from sentinel.observability.logging import log_event
from sentinel.services.http import HttpTransport, status_reason
from sentinel.services.redact import redact_json


def require_api_key(provider: str, api_key: SecretStr | None) -> str:
    """Return the key or raise. The key is not included in the error or the log."""
    text = configured_secret(api_key)
    if text is None:
        log_failure(provider, "not_configured")
        raise ConfigurationError(provider)
    return text


def request_json(
    transport: HttpTransport,
    *,
    provider: str,
    method: str,
    url: str,
    headers: Mapping[str, str],
    params: Mapping[str, str] | None,
    timeout_seconds: float,
    secret: str | None,
) -> dict[str, Any]:
    """Return redacted JSON or raise. The caller logs success after it parses."""
    try:
        result = transport.request(
            method,
            url,
            headers=headers,
            params=params,
            timeout_seconds=timeout_seconds,
        )
    except ProviderError as exc:
        log_failure(provider, exc.reason)
        raise ProviderError(provider, exc.reason) from None
    if result.status_code != 200:
        reason = status_reason(result.status_code)
        log_failure(provider, reason)
        raise ProviderError(provider, reason)
    if result.body is None:
        log_failure(provider, "invalid_response")
        raise ProviderError(provider, "invalid_response")
    return redact_json(result.body, secret)


def log_ok(provider: str) -> None:
    log_event("sentinel.providers", logging.INFO, "provider_lookup", provider=provider, status="ok")


def log_failure(provider: str, reason: str) -> None:
    log_event(
        "sentinel.providers",
        logging.WARNING,
        "provider_lookup",
        provider=provider,
        status="error",
        reason=reason,
    )
