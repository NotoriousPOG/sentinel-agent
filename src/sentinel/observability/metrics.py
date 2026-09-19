"""In-process investigation counters.

``GET /metrics`` reads this module. It does not read PostgreSQL and it does
not copy alert documents. Counts reset when the process starts. A later
analyst review updates the status of an investigation this process already
recorded. It does not invent a row for an investigation this process never ran.
"""

from dataclasses import dataclass
from decimal import Decimal
from threading import Lock

from sentinel.schemas.investigation import InvestigationStatus

_lock = Lock()


@dataclass
class _Run:
    status: str
    tokens: int
    tool_errors: int


_runs: dict[str, _Run] = {}


@dataclass(frozen=True)
class MetricsSnapshot:
    """Counts only. No alert text, command lines, usernames, or keys."""

    investigations_total: int
    investigations_by_status: dict[str, int]
    tool_errors: int
    tokens_total: int
    estimated_cost_usd: str


def record_investigation(
    investigation_id: str,
    status: str,
    tokens: int,
    tool_errors: int,
) -> None:
    """Replace the counters for one investigation id. One id is one run."""
    with _lock:
        _runs[investigation_id] = _Run(
            status=status,
            tokens=tokens,
            tool_errors=tool_errors,
        )


def update_investigation_status(investigation_id: str, status: str) -> None:
    """Move a recorded run to a new status. Unknown ids are ignored."""
    with _lock:
        run = _runs.get(investigation_id)
        if run is not None:
            run.status = status


def snapshot(usd_per_million_tokens: float | None) -> MetricsSnapshot:
    """Aggregate the runs recorded in this process."""
    with _lock:
        by_status = {status.value: 0 for status in InvestigationStatus}
        tokens = 0
        tool_errors = 0
        for run in _runs.values():
            by_status[run.status] = by_status.get(run.status, 0) + 1
            tokens += run.tokens
            tool_errors += run.tool_errors
        total = len(_runs)
    return MetricsSnapshot(
        investigations_total=total,
        investigations_by_status=by_status,
        tool_errors=tool_errors,
        tokens_total=tokens,
        estimated_cost_usd=format_cost(tokens, usd_per_million_tokens),
    )


def reset_metrics() -> None:
    """Drop process counters. Tests call this so cases do not share a total."""
    with _lock:
        _runs.clear()


def format_cost(tokens: int, usd_per_million_tokens: float | None) -> str:
    """Return a decimal string. Unset price is ``0``, not an implied model rate.

    A configured ``0`` is also ``0``. This function does not contain a price.
    """
    if usd_per_million_tokens is None:
        return "0"
    amount = (Decimal(tokens) * Decimal(str(usd_per_million_tokens))) / Decimal(1_000_000)
    quantized = amount.quantize(Decimal("0.000001"))
    if quantized == 0:
        return "0"
    return format(quantized, "f")
