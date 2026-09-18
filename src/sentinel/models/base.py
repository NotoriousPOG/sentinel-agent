"""SQLAlchemy models.

Alert rows live in ``models/alert.py``. Investigation tables are milestone 4
and are not created here.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for ORM models."""
