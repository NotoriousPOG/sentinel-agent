"""One scope per investigation: correlation id, span, and counters."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from opentelemetry.trace import Span

from sentinel.observability.logging import log_event, reset_correlation_id, set_correlation_id
from sentinel.observability.metrics import record_investigation
from sentinel.observability.tracing import get_tracer
from sentinel.schemas.investigation import InvestigationState

_LOGGER = "sentinel.investigation"

_observation: ContextVar["Observation | None"] = ContextVar(
    "sentinel_observation",
    default=None,
)


class Observation:
    """Mutable counters for the investigation currently on this task."""

    def __init__(self, span: Span, investigation_id: str) -> None:
        self.span = span
        self.investigation_id = investigation_id
        self.tool_errors = 0
        self._finished = False

    def finish(self, state: InvestigationState) -> None:
        """Record the terminal state. Does not copy the alert or the error text."""
        if self._finished:
            return
        self._finished = True
        self.span.set_attribute("investigation.status", state.status.value)
        self.span.set_attribute("investigation.tokens_used", state.tokens_used)
        self.span.set_attribute("investigation.tool_errors", self.tool_errors)
        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_finished",
            status=state.status.value,
            tokens_used=state.tokens_used,
            tool_errors=self.tool_errors,
        )
        record_investigation(
            state.investigation_id,
            state.status.value,
            state.tokens_used,
            self.tool_errors,
        )


@contextmanager
def investigation_scope(investigation_id: str) -> Iterator[Observation]:
    """Bind logs and one span to ``investigation_id`` for the duration of the run."""
    token = set_correlation_id(investigation_id)
    tracer = get_tracer()
    with tracer.start_as_current_span("investigation") as span:
        span.set_attribute("correlation_id", investigation_id)
        span.set_attribute("investigation_id", investigation_id)
        observation = Observation(span, investigation_id)
        obs_token = _observation.set(observation)
        log_event(
            _LOGGER,
            logging.INFO,
            "investigation_started",
            investigation_id=investigation_id,
        )
        try:
            yield observation
        except Exception as exc:
            span.set_attribute("error.type", type(exc).__name__)
            log_event(
                _LOGGER,
                logging.ERROR,
                "investigation_aborted",
                error_type=type(exc).__name__,
            )
            raise
        finally:
            _observation.reset(obs_token)
            reset_correlation_id(token)


def note_tool_error(kind: str) -> None:
    """Count a failed tool invocation. ``kind`` is a fixed code, not a payload."""
    observation = _observation.get()
    if observation is not None:
        observation.tool_errors += 1
    log_event(_LOGGER, logging.WARNING, "tool_error", kind=kind)


def note_tool_finished(tool: str) -> None:
    """Record that a tool returned. Arguments and ``raw`` are not logged."""
    log_event(
        _LOGGER,
        logging.INFO,
        "tool_finished",
        tool=tool,
        status="ok",
    )
