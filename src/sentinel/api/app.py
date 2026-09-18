"""ASGI application factory."""

import logging

from fastapi import FastAPI

from sentinel import __version__
from sentinel.api.exception_handlers import register_exception_handlers
from sentinel.api.routes.alerts import router as alerts_router
from sentinel.api.routes.health import router as health_router
from sentinel.api.routes.investigations import router as investigations_router
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
    """Build the API. Importing it does not connect to PostgreSQL or call a model."""
    settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(
        title="Sentinel Agent",
        version=__version__,
        description=(
            "SOC investigation API. A verified report waits for analyst review. "
            "Approving the conclusion completes the investigation. Approving "
            "remediation stores that decision and does not run an action. "
            "GET /metrics returns 501."
        ),
    )
    register_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(alerts_router)
    application.include_router(investigations_router)
    application.include_router(reserved_router)
    return application


app = create_app()
