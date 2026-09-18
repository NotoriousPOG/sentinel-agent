"""SQLAlchemy models.

No tables yet. Alert and investigation tables land with the code that writes
them (milestones 2 and 4).
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for future ORM models."""
