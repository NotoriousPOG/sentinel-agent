"""SQLAlchemy models.

Alert rows live in ``models/alert.py``. Investigation rows live in
``models/investigation.py``.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for ORM models."""
