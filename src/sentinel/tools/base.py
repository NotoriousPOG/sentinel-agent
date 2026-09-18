"""Closed tool protocol."""

from typing import Protocol

from pydantic import BaseModel

from sentinel.schemas.tools import ToolName


class SecurityTool(Protocol):
    """One named tool. ``run`` receives an already-validated input model."""

    name: ToolName

    def run(self, tool_input: BaseModel) -> BaseModel:
        """Execute the tool against its provider. Invalid names never reach ``run``."""
        ...
