"""Budget predicates. None of these call a provider or sleep."""

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import datetime

from sentinel.errors import BudgetExhausted, DuplicateToolCall, TransitionRejected
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus
from sentinel.schemas.patterns import TOOL_CALL_KEY_RE
from sentinel.schemas.timestamps import require_aware


def can_call_tool(state: InvestigationState) -> bool:
    """True only while investigating and at least one tool call remains."""
    return (
        state.status is InvestigationStatus.INVESTIGATING
        and state.tool_calls_made < state.max_tool_calls
    )


def is_past_deadline(state: InvestigationState, now: datetime) -> bool:
    instant = require_aware(now)
    return instant >= state.deadline_at


def assert_can_spend_tokens(state: InvestigationState, requested: int) -> None:
    if requested < 0:
        raise ValueError("requested token spend must be non-negative")
    if state.tokens_used + requested > state.token_budget:
        raise BudgetExhausted(
            f"token budget {state.token_budget} would be exceeded "
            f"({state.tokens_used} used, {requested} requested)"
        )


def tool_call_key(tool: str, arguments: Mapping[str, object]) -> str:
    """Stable id for one tool name plus JSON arguments. Not a cache."""
    if not tool.strip():
        raise ValueError("tool name must be non-empty")
    payload = {"arguments": _json_value(dict(arguments)), "tool": tool}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def record_tool_call(state: InvestigationState, key: str, *, now: datetime) -> InvestigationState:
    """Count one tool call. Does not execute the tool or store its result."""
    instant = require_aware(now)
    if not TOOL_CALL_KEY_RE.fullmatch(key):
        raise ValueError("tool call key must be a sha256 hex digest")
    if state.status is not InvestigationStatus.INVESTIGATING:
        raise TransitionRejected("tool calls are only recorded while INVESTIGATING")
    if not can_call_tool(state):
        raise BudgetExhausted("tool call budget exhausted")
    if key in state.seen_tool_calls:
        raise DuplicateToolCall(key)
    return state.model_copy(
        update={
            "tool_calls_made": state.tool_calls_made + 1,
            "seen_tool_calls": [*state.seen_tool_calls, key],
            "updated_at": instant,
        }
    )


def _json_value(value: object) -> object:
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("tool arguments cannot contain non-finite floats")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("tool argument keys must be strings")
            normalized[key] = _json_value(item)
        return normalized
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    raise TypeError(f"tool arguments must be JSON values, got {type(value).__name__}")
