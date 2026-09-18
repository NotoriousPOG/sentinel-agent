"""Persisted investigation.

The document column is portable JSON so the same Alembic revision applies on
SQLite (tests) and PostgreSQL. It is the ``InvestigationState``, including
evidence, tool history, errors, and budgets.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.models.base import Base


class InvestigationRecord(Base):
    """One investigation. ``alert_id`` points at a stored alert and is not a foreign key."""

    __tablename__ = "investigations"

    investigation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
