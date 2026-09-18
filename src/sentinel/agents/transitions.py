"""Legal investigation transitions.

``COMPLETE`` and ``FAILED`` are sinks. The only cycles return to
``INVESTIGATING``, and each return spends one retry. This module does not call
tools or a model.
"""

from datetime import datetime, timedelta

from sentinel.config.settings import Settings
from sentinel.errors import TransitionRejected
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus
from sentinel.schemas.timestamps import require_aware

TERMINAL_STATUSES = frozenset({InvestigationStatus.COMPLETE, InvestigationStatus.FAILED})

ALLOWED_TRANSITIONS: dict[InvestigationStatus, frozenset[InvestigationStatus]] = {
    InvestigationStatus.RECEIVED: frozenset(
        {InvestigationStatus.VALIDATING, InvestigationStatus.FAILED}
    ),
    InvestigationStatus.VALIDATING: frozenset(
        {InvestigationStatus.INVESTIGATING, InvestigationStatus.FAILED}
    ),
    InvestigationStatus.INVESTIGATING: frozenset(
        {InvestigationStatus.VERIFYING, InvestigationStatus.FAILED}
    ),
    InvestigationStatus.VERIFYING: frozenset(
        {
            InvestigationStatus.AWAITING_REVIEW,
            InvestigationStatus.INVESTIGATING,
            InvestigationStatus.FAILED,
        }
    ),
    InvestigationStatus.AWAITING_REVIEW: frozenset(
        {
            InvestigationStatus.COMPLETE,
            InvestigationStatus.INVESTIGATING,
            InvestigationStatus.FAILED,
        }
    ),
    InvestigationStatus.COMPLETE: frozenset(),
    InvestigationStatus.FAILED: frozenset(),
}

_RETRY_SOURCES = frozenset({InvestigationStatus.VERIFYING, InvestigationStatus.AWAITING_REVIEW})


def is_terminal(status: InvestigationStatus) -> bool:
    return status in TERMINAL_STATUSES


def new_investigation(
    *,
    investigation_id: str,
    alert_id: str,
    now: datetime,
    settings: Settings,
) -> InvestigationState:
    """Build a ``RECEIVED`` state from settings. ``now`` is injected by the caller."""
    instant = require_aware(now)
    return InvestigationState(
        investigation_id=investigation_id,
        alert_id=alert_id,
        status=InvestigationStatus.RECEIVED,
        tool_calls_made=0,
        max_tool_calls=settings.max_tool_calls,
        retries=0,
        max_retries=settings.max_retries,
        tokens_used=0,
        token_budget=settings.token_budget,
        started_at=instant,
        updated_at=instant,
        deadline_at=instant + timedelta(seconds=settings.investigation_timeout_seconds),
    )


def transition(
    state: InvestigationState,
    new_status: InvestigationStatus,
    *,
    now: datetime,
    error: str | None = None,
) -> InvestigationState:
    """Return a new state. The input object is not mutated.

    ``FAILED`` requires ``error``. ``COMPLETE`` is only legal from
    ``AWAITING_REVIEW`` and clears ``error``.
    """
    instant = require_aware(now)
    allowed = ALLOWED_TRANSITIONS[state.status]
    if new_status not in allowed:
        raise TransitionRejected(f"cannot move from {state.status.value} to {new_status.value}")

    retries = state.retries
    if state.status in _RETRY_SOURCES and new_status is InvestigationStatus.INVESTIGATING:
        if state.retries >= state.max_retries:
            raise TransitionRejected(
                f"retry budget exhausted ({state.retries}/{state.max_retries})"
            )
        retries = state.retries + 1

    if new_status is InvestigationStatus.FAILED:
        if error is None or not error.strip():
            raise TransitionRejected("FAILED requires an error string")
        next_error: str | None = error.strip()
    elif new_status is InvestigationStatus.COMPLETE:
        next_error = None
    else:
        next_error = error if error is not None else state.error

    return state.model_copy(
        update={
            "status": new_status,
            "retries": retries,
            "updated_at": instant,
            "error": next_error,
        }
    )
