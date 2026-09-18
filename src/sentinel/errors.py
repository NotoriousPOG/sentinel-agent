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


class UnknownTool(SentinelError):
    """The tool name is not in the closed set. There is no default tool."""

    def __init__(self, name: str) -> None:
        self.name = name[:64]
        super().__init__("unknown tool")


class ConfigurationError(SentinelError):
    """A provider has no credential. This is not a benign verdict."""

    def __init__(self, provider: str) -> None:
        self.provider = provider
        super().__init__(f"{provider} is not configured")


class ProviderError(SentinelError):
    """A lookup failed or timed out. ``reason`` is a token, not a response body."""

    def __init__(self, provider: str, reason: str) -> None:
        self.provider = provider
        self.reason = reason
        super().__init__(f"{provider} lookup failed: {reason}")


class InvestigationNotFound(SentinelError):
    """No stored investigation uses this id. The id is not repeated in the message."""

    def __init__(self) -> None:
        super().__init__("investigation was not found")


class ModelOutputInvalid(SentinelError):
    """The model text is not an instance of the response model.

    ``detail`` is validator text we produced. ``raw_text`` is the model output
    and is data, not an instruction. Neither field is a place for an API key.
    The exception message itself carries neither value.
    """

    def __init__(self, *, raw_text: str, detail: str) -> None:
        self.raw_text = raw_text[:20_000]
        cleaned = detail.strip()[:2000]
        self.detail = cleaned or "response did not match the required schema"
        super().__init__("model output failed schema validation")


class LlmTransportError(SentinelError):
    """The model endpoint failed before a usable completion.

    This is not an investigation retry and it is not a schema repair.
    ``reason`` is a short token. The exception message does not include it,
    so a transport library's text cannot ride along.
    """

    def __init__(self, reason: str) -> None:
        self.reason = _llm_reason(reason)
        super().__init__("llm transport failed")


def _llm_reason(reason: str) -> str:
    token = reason.strip()
    if token in {"timeout", "transport", "invalid_response"}:
        return token
    suffix = token.removeprefix("http_")
    if token.startswith("http_") and suffix.isdigit():
        return token
    return "transport"


def prefix_issues(issues: Sequence[FieldIssue], prefix: str) -> tuple[FieldIssue, ...]:
    """Qualify field paths so API errors point at the request body."""
    return tuple(FieldIssue(code=issue.code, field=f"{prefix}.{issue.field}") for issue in issues)
