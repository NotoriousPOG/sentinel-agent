"""Builders for schema tests. Not a threat-intel fixture set."""

from datetime import UTC, datetime

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


def alert_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "alert_id": "alert-1",
        "timestamp": "2026-09-18T12:00:00+00:00",
        "source": "unit-test",
    }
    payload.update(overrides)
    return payload
