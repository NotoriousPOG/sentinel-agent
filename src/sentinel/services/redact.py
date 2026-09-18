"""Remove a configured secret from provider JSON before it is stored."""

from typing import Any


def redact_json(value: dict[str, Any], secret: str | None) -> dict[str, Any]:
    """Return a copy of ``value`` with ``secret`` replaced.

    Short-circuit when there is no secret. Callers must not log ``secret``.
    """
    if secret is None or secret == "":
        return value
    cleaned = _redact(value, secret)
    if not isinstance(cleaned, dict):
        raise TypeError("redact_json expected an object")
    return cleaned


def _redact(value: object, secret: str) -> object:
    if isinstance(value, str):
        return value.replace(secret, "[redacted]")
    if isinstance(value, list):
        return [_redact(item, secret) for item in value]
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("provider JSON keys must be strings")
            cleaned[key.replace(secret, "[redacted]")] = _redact(item, secret)
        return cleaned
    return value
