"""add ip_address + sources to assets, priority to plugin_configs

Revision ID: 004_ip_and_sources
Revises: 003_plugin_tables
Create Date: 2026-04-23

Enables cross-connector deduplication:
- assets.sources JSONB stores {"keys": {plugin_id: external_key},
  "fields": {field_name: plugin_id}} — per-field provenance.
- assets.ip_address is promoted to a first-class column (was stored
  only in notes by some connectors).
- asset_plugin_configs.priority decides which connector wins when two
  connectors try to write the same field on the same asset (higher
  value = higher priority).
- Functional index on lower(nom) supports the fallback hostname match.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "004_ip_and_sources"
down_revision = "003_plugin_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("ip_address", sa.String(64), nullable=True, server_default=""),
    )
    op.add_column(
        "assets",
        sa.Column("sources", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "asset_plugin_configs",
        sa.Column("priority", sa.Integer, nullable=False, server_default="100"),
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_nom_lower ON assets (project_id, lower(nom))")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_assets_nom_lower")
    op.drop_column("asset_plugin_configs", "priority")
    op.drop_column("assets", "sources")
    op.drop_column("assets", "ip_address")
