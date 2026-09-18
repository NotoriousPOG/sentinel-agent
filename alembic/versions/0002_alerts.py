"""Create the alerts table.

Revision ID: 0002_alerts
Revises: 0001_initial
Create Date: 2026-09-18

``document`` is generic JSON, not JSONB, so this revision runs on SQLite and PostgreSQL.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_alerts"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(length=256), primary_key=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("alerts")
