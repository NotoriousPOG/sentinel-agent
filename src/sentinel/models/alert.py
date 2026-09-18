"""Persisted alert.

The document column is portable JSON so the same Alembic revision applies on
SQLite (tests) and PostgreSQL (the deployment and the CI service).
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.models.base import Base


class AlertRecord(Base):
    """One normalized alert. ``alert_id`` is the primary key, so a replay cannot insert twice."""

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
