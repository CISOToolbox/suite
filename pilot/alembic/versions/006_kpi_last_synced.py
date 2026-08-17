"""kpi_definition.last_synced_at

Revision ID: 006_kpi_last_synced
Revises: 005_evidence_cache
Create Date: 2026-07-06

Wall-clock of the last SUCCESSFUL KPI value sync (auto scheduler or a manual
connector run), surfaced on the indicator cards. Nullable; back-filled to NULL
for existing rows (shown as never-synced until the next successful pass).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006_kpi_last_synced"
down_revision = "005_evidence_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "kpi_definition",
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("kpi_definition", "last_synced_at")
