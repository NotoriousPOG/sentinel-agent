"""Bounded investigation loop.

The only status changes in the tool loop go through ``transition``. Budgets
are the predicates in ``agents/budgets.py``. The loop stops at ``VERIFYING``.
``finalize_investigation`` then stores a verified report and moves to
``AWAITING_REVIEW``, or ``FAILED``. ``COMPLETE`` is not produced here.
"""

from collections.abc import Sequence
from datetime import datetime

from pydantic import ValidationError

from sentinel.agents.budgets import (
    assert_can_spend_tokens,
    can_call_tool,
    is_past_deadline,
    record_tool_call,
)
from sentinel.agents.decision import ModelTurn, TurnAction
from sentinel.agents.prompts import (
    initial_messages,
    repair_message,
    tool_result_message,
)
from sentinel.agents.reporting import finalize_investigation
from sentinel.agents.transitions import transition
from sentinel.errors import (
    BudgetExhausted,
    ConfigurationError,
    LlmTransportError,
    ModelOutputInvalid,
    ProviderError,
    UnknownTool,
)
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.investigation import (
    InvestigationState,
    InvestigationStatus,
    ModelOutputRecord,
    ToolHistoryEntry,
)
from sentinel.services.clock import Clock
from sentinel.services.llm import LlmMessage, LlmProvider, LlmRole
from sentinel.tools.registry import ToolRegistry

_SCHEMA_FAILURE = "model output failed schema validation"
_UNKNOWN_TOOL = "unknown tool"
_INVALID_ARGUMENTS = "invalid tool arguments"


def run_investigation(
    state: InvestigationState,
    *,
    alert: NormalizedAlert,
    llm: LlmProvider,
    tools: ToolRegistry,
    clock: Clock,
    max_repair_attempts: int,
) -> InvestigationState:
    """Walk one investigation until a verified report is stored, or ``FAILED``.

    The tool loop stops, and does not hang, when any of these is true:

    - the model returns finish
    - ``tool_calls_made`` reaches ``max_tool_calls`` (report step if any
      evidence was stored, otherwise ``FAILED``)
    - the model repeats a tool key already recorded on this state
    - schema-invalid output, an unknown tool name, or invalid tool arguments
      have already used ``max_repair_attempts`` repairs
    - ``is_past_deadline`` is true, or the token predicate refuses the next
      model call
    - the model endpoint or a tool provider raises a transport or configuration
      error. Those are not investigation retries and they are not repeated

    After ``VERIFYING``, the report step may move to ``AWAITING_REVIEW``.
    ``COMPLETE`` is not entered here.
    """
    if state.status is not InvestigationStatus.RECEIVED:
        raise ValueError("executor starts from RECEIVED")
    now = clock.now()
    state = transition(state, InvestigationStatus.VALIDATING, now=now)
    if alert.alert_id != state.alert_id:
        return _fail(state, "alert id does not match the investigation", clock.now())
    state = transition(state, InvestigationStatus.INVESTIGATING, now=clock.now())

    messages = initial_messages(alert)
    repairs_used = state.repair_attempts
    while True:
        now = clock.now()
        if is_past_deadline(state, now):
            return _fail(state, "deadline exceeded", now)
        prompt_tokens = _message_tokens(messages)
        try:
            assert_can_spend_tokens(state, prompt_tokens)
        except BudgetExhausted:
            return _fail(state, "token budget exhausted", now)

        try:
            turn = llm.complete_structured(messages, ModelTurn)
        except ModelOutputInvalid as exc:
            state, repairs_used, failed = _repair(
                state,
                messages,
                detail=exc.detail,
                raw_text=exc.raw_text,
                now=clock.now(),
                repairs_used=repairs_used,
                max_repair_attempts=max_repair_attempts,
                terminal_error=_SCHEMA_FAILURE,
            )
            if failed:
                return state
            continue
        except LlmTransportError as exc:
            return _fail(state, f"llm transport failed: {exc.reason}", clock.now())

        response_tokens = _text_tokens(turn.model_dump_json())
        try:
            assert_can_spend_tokens(
                state.model_copy(update={"tokens_used": state.tokens_used + prompt_tokens}),
                response_tokens,
            )
        except BudgetExhausted:
            state = state.model_copy(
                update={"tokens_used": state.tokens_used + prompt_tokens, "updated_at": clock.now()}
            )
            return _fail(state, "token budget exhausted", clock.now())
        state = state.model_copy(
            update={
                "tokens_used": state.tokens_used + prompt_tokens + response_tokens,
                "updated_at": clock.now(),
            }
        )

        if turn.action is TurnAction.FINISH:
            return _after_verifying(
                state,
                alert=alert,
                llm=llm,
                clock=clock,
                max_repair_attempts=max_repair_attempts,
            )

        now = clock.now()
        if is_past_deadline(state, now):
            return _fail(state, "deadline exceeded", now)
        if not can_call_tool(state):
            return _stop_for_tool_budget(
                state,
                alert=alert,
                llm=llm,
                clock=clock,
                max_repair_attempts=max_repair_attempts,
            )

        raw_turn = turn.model_dump_json()
        tool_name = turn.tool if turn.tool is not None else ""
        try:
            execution = tools.call(tool_name, turn.arguments)
        except UnknownTool:
            state, repairs_used, failed = _repair(
                state,
                messages,
                detail=_UNKNOWN_TOOL,
                raw_text=raw_turn,
                now=clock.now(),
                repairs_used=repairs_used,
                max_repair_attempts=max_repair_attempts,
                terminal_error=_UNKNOWN_TOOL,
            )
            if failed:
                return state
            continue
        except ValidationError:
            state, repairs_used, failed = _repair(
                state,
                messages,
                detail=_INVALID_ARGUMENTS,
                raw_text=raw_turn,
                now=clock.now(),
                repairs_used=repairs_used,
                max_repair_attempts=max_repair_attempts,
                terminal_error=_INVALID_ARGUMENTS,
            )
            if failed:
                return state
            continue
        except ProviderError as exc:
            return _fail(state, f"{exc.provider} lookup failed: {exc.reason}", clock.now())
        except ConfigurationError as exc:
            return _fail(state, f"{exc.provider} is not configured", clock.now())

        now = clock.now()
        if execution.key in state.seen_tool_calls:
            if state.evidence:
                return _after_verifying(
                    state,
                    alert=alert,
                    llm=llm,
                    clock=clock,
                    max_repair_attempts=max_repair_attempts,
                )
            return _fail(state, "duplicate tool call", now)

        state = record_tool_call(state, execution.key, now=now)
        evidence = execution.evidence()
        history = ToolHistoryEntry(
            key=execution.key,
            tool=execution.tool.value,
            arguments=execution.query,
            from_cache=execution.from_cache,
            evidence_id=evidence.evidence_id,
        )
        state = state.model_copy(
            update={
                "evidence": [*state.evidence, evidence],
                "tool_history": [*state.tool_history, history],
            }
        )
        messages.append(
            LlmMessage(role=LlmRole.ASSISTANT, content=raw_turn),
        )
        messages.append(
            tool_result_message(
                tool=execution.tool.value,
                arguments=execution.query,
                result=execution.output.model_dump(mode="json"),
                from_cache=execution.from_cache,
            )
        )
        if not can_call_tool(state):
            return _stop_for_tool_budget(
                state,
                alert=alert,
                llm=llm,
                clock=clock,
                max_repair_attempts=max_repair_attempts,
            )


def _repair(
    state: InvestigationState,
    messages: list[LlmMessage],
    *,
    detail: str,
    raw_text: str,
    now: datetime,
    repairs_used: int,
    max_repair_attempts: int,
    terminal_error: str,
) -> tuple[InvestigationState, int, bool]:
    bounded_raw = raw_text.strip()[:20_000] or "(empty)"
    bounded_detail = detail.strip()[:2000] or _SCHEMA_FAILURE
    recorded = state.model_copy(
        update={
            "error": bounded_detail,
            "updated_at": now,
            "model_outputs": [
                *state.model_outputs,
                ModelOutputRecord(raw_text=bounded_raw, error=bounded_detail),
            ],
        }
    )
    if repairs_used >= max_repair_attempts:
        return _fail(recorded, terminal_error, now), repairs_used, True
    repairs_used += 1
    recorded = recorded.model_copy(update={"repair_attempts": repairs_used})
    messages.append(repair_message(detail=bounded_detail, raw_text=bounded_raw))
    return recorded, repairs_used, False


def _stop_for_tool_budget(
    state: InvestigationState,
    *,
    alert: NormalizedAlert,
    llm: LlmProvider,
    clock: Clock,
    max_repair_attempts: int,
) -> InvestigationState:
    if state.evidence:
        return _after_verifying(
            state,
            alert=alert,
            llm=llm,
            clock=clock,
            max_repair_attempts=max_repair_attempts,
        )
    return _fail(state, "tool call budget exhausted", clock.now())


def _after_verifying(
    state: InvestigationState,
    *,
    alert: NormalizedAlert,
    llm: LlmProvider,
    clock: Clock,
    max_repair_attempts: int,
) -> InvestigationState:
    verifying = _verify(state, clock.now())
    return finalize_investigation(
        verifying,
        alert=alert,
        llm=llm,
        clock=clock,
        max_repair_attempts=max_repair_attempts,
    )


def _verify(state: InvestigationState, now: datetime) -> InvestigationState:
    moved = transition(state, InvestigationStatus.VERIFYING, now=now)
    if moved.error is None:
        return moved
    return moved.model_copy(update={"error": None})


def _fail(state: InvestigationState, error: str, now: datetime) -> InvestigationState:
    text = error.strip()[:2000] or "investigation failed"
    return transition(state, InvestigationStatus.FAILED, now=now, error=text)


def _message_tokens(messages: Sequence[LlmMessage]) -> int:
    return sum(_text_tokens(message.content) for message in messages)


def _text_tokens(text: str) -> int:
    return max(1, len(text) // 4)
