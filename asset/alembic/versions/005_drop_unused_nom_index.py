"""drop unused functional index on lower(nom)

Revision ID: 005_drop_unused_nom_index
Revises: 004_ip_and_sources
Create Date: 2026-04-23

The 004 migration created ix_assets_nom_lower to speed up the fallback
hostname match across connectors. In practice the sync loads all rows
into memory once and builds a Python-side dict, so the index is never
used by the query planner — it just adds write overhead on every
insert/update. Removing it.
"""
from __future__ import annotations

from alembic import op

revision = "005_drop_unused_nom_index"
down_revision = "004_ip_and_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_assets_nom_lower")


def downgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_assets_nom_lower "
        "ON assets (project_id, lower(nom))"
    )
