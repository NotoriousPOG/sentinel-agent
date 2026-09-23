"""Shared request handling for vendor clients. No verdicts are invented here."""

import logging
import time
from collections.abc import Callable, Mapping
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


# Transient only. A 4xx other than 429, a bad body, and a missing key are not retried.
_TRANSIENT = frozenset(
    {"timeout", "transport", "http_429", "http_500", "http_502", "http_503", "http_504"}
)


def pause(
    backoff_seconds: float,
    attempt_index: int,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Wait before the next attempt. A zero backoff does not sleep."""
    if backoff_seconds <= 0:
        return
    sleep(min(backoff_seconds * (attempt_index + 1), 2.0))


def _retry(reason: str, attempt_index: int, max_attempts: int) -> bool:
    return reason in _TRANSIENT and attempt_index + 1 < max_attempts


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
    max_attempts: int = 1,
    backoff_seconds: float = 0.0,
) -> dict[str, Any]:
    """Return redacted JSON or raise. The caller logs success after it parses.

    Transient failures are tried up to ``max_attempts`` times. The last failure
    is the error that escapes. A failed attempt is not stored as a verdict.
    """
    attempts = max(1, max_attempts)
    last_reason = "transport"
    for attempt in range(attempts):
        try:
            result = transport.request(
                method,
                url,
                headers=headers,
                params=params,
                timeout_seconds=timeout_seconds,
            )
        except ProviderError as exc:
            last_reason = exc.reason
            if not _retry(exc.reason, attempt, attempts):
                log_failure(provider, exc.reason)
                raise ProviderError(provider, exc.reason) from None
            _log_retry(provider, exc.reason, attempt)
            pause(backoff_seconds, attempt)
            continue
        if result.status_code != 200:
            reason = status_reason(result.status_code)
            last_reason = reason
            if not _retry(reason, attempt, attempts):
                log_failure(provider, reason)
                raise ProviderError(provider, reason)
            _log_retry(provider, reason, attempt)
            pause(backoff_seconds, attempt)
            continue
        if result.body is None:
            log_failure(provider, "invalid_response")
            raise ProviderError(provider, "invalid_response")
        return redact_json(result.body, secret)
    log_failure(provider, last_reason)
    raise ProviderError(provider, last_reason)


def log_ok(provider: str) -> None:
    log_event("sentinel.providers", logging.INFO, "provider_lookup", provider=provider, status="ok")


def _log_retry(provider: str, reason: str, attempt_index: int) -> None:
    log_event(
        "sentinel.providers",
        logging.WARNING,
        "provider_retry",
        provider=provider,
        status="retry",
        reason=reason,
        attempt=attempt_index + 1,
    )


def log_failure(provider: str, reason: str) -> None:
    log_event(
        "sentinel.providers",
        logging.WARNING,
        "provider_lookup",
        provider=provider,
        status="error",
        reason=reason,
    )
