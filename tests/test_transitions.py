"""Transition and budget guards. There is no agent loop here."""

from datetime import timedelta

import pytest
from tests.support import NOW

from sentinel.agents.budgets import (
    assert_can_spend_tokens,
    can_call_tool,
    is_past_deadline,
    record_tool_call,
    tool_call_key,
)
from sentinel.agents.transitions import is_terminal, new_investigation, transition
from sentinel.config.settings import Settings
from sentinel.errors import BudgetExhausted, DuplicateToolCall, TransitionRejected
from sentinel.schemas.investigation import InvestigationState, InvestigationStatus


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+pysqlite:///:memory:",
        max_tool_calls=2,
        max_retries=2,
        investigation_timeout_seconds=120,
        token_budget=100,
    )


def _received() -> InvestigationState:
    return new_investigation(
        investigation_id="inv-1",
        alert_id="alert-1",
        now=NOW,
        settings=_settings(),
    )


def test_complete_only_from_awaiting_review() -> None:
    state = _received()
    for status in (
        InvestigationStatus.VALIDATING,
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.VERIFYING,
        InvestigationStatus.AWAITING_REVIEW,
    ):
        state = transition(state, status, now=NOW)
    assert not is_terminal(state.status)
    done = transition(state, InvestigationStatus.COMPLETE, now=NOW)
    assert state.status is InvestigationStatus.AWAITING_REVIEW
    assert done.status is InvestigationStatus.COMPLETE
    assert done.error is None
    assert is_terminal(done.status)
    with pytest.raises(TransitionRejected):
        transition(done, InvestigationStatus.INVESTIGATING, now=NOW)


def test_complete_is_unreachable_from_verifying() -> None:
    state = _received()
    for status in (
        InvestigationStatus.VALIDATING,
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.VERIFYING,
    ):
        state = transition(state, status, now=NOW)
    with pytest.raises(TransitionRejected, match="cannot move from VERIFYING to COMPLETE"):
        transition(state, InvestigationStatus.COMPLETE, now=NOW)


def test_retry_budget_is_finite() -> None:
    state = _received()
    state = transition(state, InvestigationStatus.VALIDATING, now=NOW)
    state = transition(state, InvestigationStatus.INVESTIGATING, now=NOW)
    for _ in range(2):
        state = transition(state, InvestigationStatus.VERIFYING, now=NOW)
        state = transition(state, InvestigationStatus.INVESTIGATING, now=NOW)
    state = transition(state, InvestigationStatus.VERIFYING, now=NOW)
    with pytest.raises(TransitionRejected, match="retry budget"):
        transition(state, InvestigationStatus.INVESTIGATING, now=NOW)


def test_failed_requires_an_error_and_does_not_mutate_input() -> None:
    state = _received()
    with pytest.raises(TransitionRejected, match="error"):
        transition(state, InvestigationStatus.FAILED, now=NOW)
    assert state.status is InvestigationStatus.RECEIVED
    failed = transition(state, InvestigationStatus.FAILED, now=NOW, error="validation failed")
    assert state.status is InvestigationStatus.RECEIVED
    assert failed.status is InvestigationStatus.FAILED
    assert failed.error == "validation failed"


def test_tool_budget_and_duplicates() -> None:
    state = _received()
    state = transition(state, InvestigationStatus.VALIDATING, now=NOW)
    state = transition(state, InvestigationStatus.INVESTIGATING, now=NOW)
    assert can_call_tool(state)
    key = tool_call_key("lookup_ip", {"ip": "203.0.113.10"})
    same = tool_call_key("lookup_ip", {"ip": "203.0.113.10"})
    assert key == same
    reordered = tool_call_key("lookup_ip", {"ip": "203.0.113.10"})
    assert reordered == key
    original_keys = list(state.seen_tool_calls)
    state = record_tool_call(state, key, now=NOW)
    assert original_keys == []
    state = record_tool_call(state, tool_call_key("lookup_hash", {"file_hash": "ab"}), now=NOW)
    assert not can_call_tool(state)
    with pytest.raises(BudgetExhausted):
        record_tool_call(state, tool_call_key("lookup_domain", {"domain": "example.com"}), now=NOW)
    earlier = transition(
        _received(),
        InvestigationStatus.VALIDATING,
        now=NOW,
    )
    earlier = transition(earlier, InvestigationStatus.INVESTIGATING, now=NOW)
    earlier = record_tool_call(earlier, key, now=NOW)
    with pytest.raises(DuplicateToolCall):
        record_tool_call(earlier, key, now=NOW)


def test_deadline_and_tokens() -> None:
    state = _received()
    assert not is_past_deadline(state, NOW)
    assert is_past_deadline(state, NOW + timedelta(seconds=120))
    assert_can_spend_tokens(state, 100)
    with pytest.raises(BudgetExhausted):
        assert_can_spend_tokens(state, 101)
    with pytest.raises(TypeError):
        tool_call_key("lookup_ip", {"when": NOW})
