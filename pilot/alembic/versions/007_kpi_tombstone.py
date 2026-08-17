"""kpi_tombstone — persist KPI deletions across restarts

Revision ID: 007_kpi_tombstone
Revises: 006_kpi_last_synced
Create Date: 2026-07-06

The catalogue seed re-inserts any catalogue KPI missing from the DB on every
restart, which resurrected a KPI an admin had deleted. This tombstone table
records deleted codes; ``seed_kpi_catalog`` skips them so the deletion sticks.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "007_kpi_tombstone"
down_revision = "006_kpi_last_synced"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kpi_tombstone",
        sa.Column("code", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column(
            "deleted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("kpi_tombstone")
