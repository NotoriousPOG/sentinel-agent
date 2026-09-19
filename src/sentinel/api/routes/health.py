"""Liveness. This route does not touch the database."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from sentinel import __version__
from sentinel.config.settings import get_settings

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]
    service: Literal["sentinel-agent"]
    version: str
    demo_mode: bool


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Process liveness. Reports ``demo_mode``. This route does not start an investigation."""
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service="sentinel-agent",
        version=__version__,
        demo_mode=settings.demo_mode,
    )
