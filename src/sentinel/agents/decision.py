"""Structured model turn. This is not an incident report."""

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TurnAction(StrEnum):
    CALL_TOOL = "call_tool"
    FINISH = "finish"


class ModelTurn(BaseModel):
    """One model decision. ``extra`` is forbidden so a report cannot hide in here."""

    model_config = ConfigDict(extra="forbid")

    action: TurnAction
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _action_matches_fields(self) -> Self:
        if self.action is TurnAction.CALL_TOOL:
            if self.tool is None or not self.tool.strip():
                raise ValueError("call_tool requires a tool name")
            return self
        if self.tool is not None or self.arguments:
            raise ValueError("finish cannot include a tool call")
        return self
