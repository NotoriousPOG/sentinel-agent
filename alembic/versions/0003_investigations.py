"""Create the investigations table.

Revision ID: 0003_investigations
Revises: 0002_alerts
Create Date: 2026-09-18

``document`` is generic JSON, not JSONB, so this revision runs on SQLite and PostgreSQL.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_investigations"
down_revision: str | None = "0002_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("investigation_id", sa.String(length=128), primary_key=True),
        sa.Column("alert_id", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
    )
    op.create_index("ix_investigations_alert_id", "investigations", ["alert_id"])


def downgrade() -> None:
    op.drop_index("ix_investigations_alert_id", table_name="investigations")
    op.drop_table("investigations")
