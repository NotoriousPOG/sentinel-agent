"""Liveness and readiness. ``/health`` does not touch the database."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from sentinel import __version__
from sentinel.api.deps import get_db
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


class ReadinessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "unavailable"]
    service: Literal["sentinel-agent"]
    database: Literal["ok", "unavailable"]


@router.get("/ready", response_model=ReadinessResponse)
def ready(session: Annotated[Session, Depends(get_db)]) -> ReadinessResponse | JSONResponse:
    """Readiness. Runs ``SELECT 1``. A database error is 503 and does not echo the URL."""
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        body = ReadinessResponse(
            status="unavailable", service="sentinel-agent", database="unavailable"
        )
        return JSONResponse(status_code=503, content=body.model_dump())
    return ReadinessResponse(status="ok", service="sentinel-agent", database="ok")
