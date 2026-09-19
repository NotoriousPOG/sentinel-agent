"""Structured logs. The correlation id is the investigation id.

Messages emitted through ``log_event`` are one JSON object. A configured
``SecretStr`` is removed from those lines. Command lines, usernames, and
provider ``raw`` are not accepted fields. ``raw`` can be logged only by
``log_raw_payload``, and only at debug when ``SENTINEL_LOG_PROVIDER_RAW`` is
set. Info never receives it.
"""

import json
import logging
from collections.abc import Mapping
from contextvars import ContextVar, Token
from typing import Any

from pydantic import ValidationError

from sentinel.config.settings import configured_secret, get_settings

_correlation_id: ContextVar[str | None] = ContextVar("sentinel_correlation_id", default=None)

_DROPPED_FIELDS = frozenset(
    {
        "alert",
        "api_key",
        "arguments",
        "authorization",
        "command_line",
        "description",
        "headers",
        "key",
        "password",
        "query",
        "raw",
        "raw_event",
        "secret",
        "title",
        "username",
    }
)

_LOGGERS = ("sentinel", "sentinel.investigation", "sentinel.providers")


class CorrelationFilter(logging.Filter):
    """Attach the current correlation id and strip configured secrets."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = current_correlation_id() or ""
        rendered = record.getMessage()
        cleaned = redact_secrets(rendered)
        if cleaned != rendered:
            record.msg = cleaned
            record.args = ()
        return True


def install_log_filter() -> None:
    """Attach the filter once. Safe to call from application startup and tests."""
    for name in _LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(item, CorrelationFilter) for item in logger.filters):
            logger.addFilter(CorrelationFilter())


def set_correlation_id(investigation_id: str) -> Token[str | None]:
    return _correlation_id.set(investigation_id)


def reset_correlation_id(token: Token[str | None]) -> None:
    _correlation_id.reset(token)


def current_correlation_id() -> str | None:
    return _correlation_id.get()


def log_event(logger_name: str, level: int, event: str, **fields: object) -> None:
    """Write one JSON line. Dropped fields are not serialized at any level."""
    payload: dict[str, object] = {
        "correlation_id": current_correlation_id(),
        "event": event,
    }
    for key, value in fields.items():
        if key in _DROPPED_FIELDS or not _plain(value):
            continue
        payload[key] = value
    logger = logging.getLogger(logger_name)
    install_log_filter()
    logger.log(level, json.dumps(payload, sort_keys=True))


def log_raw_payload(provider: str, raw: Mapping[str, Any] | str) -> None:
    """Log provider ``raw`` at debug, and only when the flag is set.

    This never uses info. Provider clients do not call it. The investigation
    path must not call it either.
    """
    if not _raw_debug_enabled():
        return
    body: dict[str, object] = {
        "correlation_id": current_correlation_id(),
        "event": "provider_raw",
        "provider": provider,
    }
    try:
        encoded_raw = json.loads(json.dumps(raw))
    except (TypeError, ValueError):
        encoded_raw = "unlogged"
    body["raw"] = encoded_raw
    try:
        line = json.dumps(body, sort_keys=True)
    except (TypeError, ValueError):
        line = json.dumps(
            {
                "correlation_id": current_correlation_id(),
                "event": "provider_raw",
                "provider": provider,
                "raw": "unlogged",
            },
            sort_keys=True,
        )
    logger = logging.getLogger("sentinel.providers")
    install_log_filter()
    logger.debug(line)


def redact_secrets(text: str) -> str:
    """Replace configured secret text. Does not log the secret it removes."""
    cleaned = text
    for secret in _secret_values():
        cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


def _plain(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _raw_debug_enabled() -> bool:
    try:
        return bool(get_settings().log_provider_raw)
    except ValidationError:
        return False


def _secret_values() -> tuple[str, ...]:
    try:
        settings = get_settings()
    except ValidationError:
        return ()
    found: list[str] = []
    for item in (
        settings.llm_api_key,
        settings.abuseipdb_api_key,
        settings.virustotal_api_key,
    ):
        text = configured_secret(item)
        if text:
            found.append(text)
    return tuple(found)


install_log_filter()
