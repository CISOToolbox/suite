"""asset measures (action plan) with auto-generation from echeances (FEAT-22)

Revision ID: 009_measures
Revises: 008_asset_licence
Create Date: 2026-06-29

Gives Asset its own remediation measures (like the other backend modules)
so they flow into Pilot's consolidated action plan, plus the columns that
support idempotent auto-generation from asset echeances:
  origine  — "manual" | "echeance"
  asset_id — soft reference to the originating asset (NOT a FK: assets are
             delete+reinserted on every blob autosave)
  auto_key — dedup signature "<asset_id>:<kind>:<date>"; NULL for manual.
             Unique (project_id, auto_key) makes the daily tick idempotent.
The table is also created by Base.metadata.create_all at startup; this
migration tracks the change for existing deployments.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "009_measures"
down_revision = "008_asset_licence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "measures",
        sa.Column("project_id", UUID(as_uuid=True),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("id", sa.String(length=20), primary_key=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("title", sa.String(length=500), nullable=False, server_default=sa.text("''")),
        sa.Column("description", sa.Text(), nullable=True, server_default=sa.text("''")),
        sa.Column("statut", sa.String(length=50), nullable=False, server_default=sa.text("'a_faire'")),
        sa.Column("responsable", sa.String(length=255), nullable=True, server_default=sa.text("''")),
        sa.Column("echeance", sa.String(length=20), nullable=True, server_default=sa.text("''")),
        sa.Column("progress_log", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("origine", sa.String(length=20), nullable=False, server_default=sa.text("'manual'")),
        sa.Column("asset_id", sa.String(length=20), nullable=True, server_default=sa.text("''")),
        sa.Column("auto_key", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_asset_measures_project_statut", "measures", ["project_id", "statut"])
    op.create_index("uq_asset_measures_auto_key", "measures", ["project_id", "auto_key"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_asset_measures_auto_key", table_name="measures")
    op.drop_index("ix_asset_measures_project_statut", table_name="measures")
    op.drop_table("measures")
