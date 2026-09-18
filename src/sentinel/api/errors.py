"""Shared 501 body for routes that are named but not built."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class NotImplementedBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["not_implemented"]
    milestone: int
    message: str


def not_implemented(milestone: int, message: str) -> NotImplementedBody:
    return NotImplementedBody(error="not_implemented", milestone=milestone, message=message)
