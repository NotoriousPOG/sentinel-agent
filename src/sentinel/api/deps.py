"""Database session dependency. Importing this module does not connect."""

from collections.abc import Iterator

from sqlalchemy.orm import Session

from sentinel.storage.session import make_engine, make_session_factory


def get_db() -> Iterator[Session]:
    """Yield a session for one request. The engine is not created at import time."""
    engine = make_engine()
    factory = make_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
