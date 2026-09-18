"""Builders for schema tests. Not a threat-intel fixture set."""

from datetime import UTC, datetime
from typing import Any

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


def alert_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "alert_id": "alert-1",
        "timestamp": "2026-09-18T12:00:00+00:00",
        "source": "unit-test",
    }
    payload.update(overrides)
    return payload


def canned_report_narrative(response_model: type[Any]) -> Any | None:
    """Safe narrative for tool-loop fakes. Does not consume a scripted tool turn."""
    from sentinel.agents.reporting import ReportNarrative

    if response_model is not ReportNarrative:
        return None
    return ReportNarrative(
        executive_summary=(
            "Collected results are attached. Classification uses stored fields only."
        ),
        analyst_notes="",
    )
