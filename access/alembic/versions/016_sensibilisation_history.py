"""si_users.sensibilisation_history — cumulative awareness training log

Revision ID: 016_sensibilisation_history
Revises: 015_measure_progress_log
Create Date: 2026-07-08

Per-training awareness history fed by the Proofpoint PSAT connector, keyed by
campaign name and never pruned. The existing `sensibilisation` bool becomes a
derived compliance state computed from the latest sync snapshot.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "016_sensibilisation_history"
down_revision = "015_measure_progress_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "si_users",
        sa.Column(
            "sensibilisation_history",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("si_users", "sensibilisation_history")
