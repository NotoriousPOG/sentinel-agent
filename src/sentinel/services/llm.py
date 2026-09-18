"""LLM port. No provider is implemented and no SDK is imported."""

from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

ModelT = TypeVar("ModelT", bound=BaseModel)


class LlmRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class LlmMessage(BaseModel):
    """One chat message.

    Untrusted alert text must not be placed in ``SYSTEM``. Milestone 7 enforces
    that when a prompt builder exists. This model only stores the role.
    """

    model_config = ConfigDict(extra="forbid")

    role: LlmRole
    content: str = Field(min_length=1, max_length=100_000)


class LlmProvider(Protocol):
    """Structured completion. Implementations must return ``response_model`` or raise."""

    def complete_structured(
        self,
        messages: Sequence[LlmMessage],
        response_model: type[ModelT],
    ) -> ModelT:
        """Return a validated model. No implementation ships in milestone 1."""
        ...
