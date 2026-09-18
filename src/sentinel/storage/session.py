"""Engine and session factory. Importing this module does not connect."""

from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel.config.settings import get_settings


def make_engine(url: str | None = None) -> Engine:
    """Build an engine. Callers own its lifetime and must ``dispose()`` it."""
    database_url = url if url is not None else get_settings().database_url
    connect_args: dict[str, Any] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)


def make_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    bound = engine if engine is not None else make_engine()
    return sessionmaker(bind=bound, autoflush=False, autocommit=False, expire_on_commit=False)
