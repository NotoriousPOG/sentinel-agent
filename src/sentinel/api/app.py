"""ASGI application factory."""

import logging

from fastapi import FastAPI

from sentinel import __version__
from sentinel.api.exception_handlers import register_exception_handlers
from sentinel.api.routes.alerts import router as alerts_router
from sentinel.api.routes.health import router as health_router
from sentinel.api.routes.reserved import router as reserved_router
from sentinel.config.settings import get_settings


def configure_logging(level: str) -> None:
    """Set the root log level without attaching a second handler in tests."""
    root = logging.getLogger()
    numeric = logging.getLevelNamesMapping()[level]
    if not root.handlers:
        logging.basicConfig(level=numeric)
    else:
        root.setLevel(numeric)


def create_app() -> FastAPI:
    """Build the API. Does not connect to PostgreSQL and does not call a model."""
    settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(
        title="Sentinel Agent",
        version=__version__,
        description=(
            "SOC investigation API. This release accepts alerts and serves liveness. "
            "Investigation, review, and metrics routes are reserved and return 501. "
            "They do not investigate or remediate."
        ),
    )
    register_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(alerts_router)
    application.include_router(reserved_router)
    return application


app = create_app()
