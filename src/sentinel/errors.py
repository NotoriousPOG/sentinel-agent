"""Expected failures.

These are raised on purpose and handled at the edge. They are not a signal
to retry blindly, and they must not be swallowed.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from sentinel.schemas.errors import ValidationCode


class SentinelError(Exception):
    """Base class for failures the application knows how to name."""


class NotImplementedCapability(SentinelError):
    """A named capability has no implementation.

    ``milestone`` is ``None`` when the type is an interface with no scheduled
    work (vendor products that are not in milestones 1-10).
    """

    def __init__(self, capability: str, *, milestone: int | None) -> None:
        self.capability = capability
        self.milestone = milestone
        if milestone is None:
            message = f"{capability} is an unimplemented interface and is not scheduled."
        else:
            message = f"{capability} is not implemented (milestone {milestone})."
        super().__init__(message)


class TransitionRejected(SentinelError):
    """The requested status change is illegal or the retry budget is spent."""


class BudgetExhausted(SentinelError):
    """A tool-call, token, or deadline budget refused more work."""


class DuplicateToolCall(SentinelError):
    """This tool name and argument set was already recorded."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"duplicate tool call {key}")


@dataclass(frozen=True, slots=True)
class FieldIssue:
    """One validation failure. ``field`` is a dotted path. Values are not stored."""

    code: ValidationCode
    field: str


class AlertValidationError(SentinelError):
    """The alert document is not acceptable. Fail closed; do not store a partial row."""

    def __init__(self, issues: Sequence[FieldIssue]) -> None:
        self.issues = tuple(issues)
        if not self.issues:
            raise ValueError("AlertValidationError requires at least one issue")
        super().__init__("alert validation failed")


class AlertNotFound(SentinelError):
    """No stored alert uses this id. The id is not repeated in the message."""

    def __init__(self) -> None:
        super().__init__("alert was not found")


def prefix_issues(issues: Sequence[FieldIssue], prefix: str) -> tuple[FieldIssue, ...]:
    """Qualify field paths so API errors point at the request body."""
    return tuple(FieldIssue(code=issue.code, field=f"{prefix}.{issue.field}") for issue in issues)
