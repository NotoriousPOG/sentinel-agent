"""Empty baseline.

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-18

No tables yet. Alert and investigation tables land with the code that writes them.
"""

from collections.abc import Sequence

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Baseline marker. Intentionally creates no tables."""


def downgrade() -> None:
    """Baseline marker. Intentionally drops nothing."""
