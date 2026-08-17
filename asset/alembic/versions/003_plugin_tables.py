"""add asset_plugin_configs + asset_sync_jobs tables

Revision ID: 003_plugin_tables
Revises: 002_assets_last_login
Create Date: 2026-04-23
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "003_plugin_tables"
down_revision = "002_assets_last_login"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_plugin_configs",
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("plugin_type", sa.String(50), nullable=False),
        sa.Column("label", sa.String(255), nullable=True, server_default=""),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("config_enc", sa.Text, nullable=True, server_default=""),
        sa.Column("filters", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("schedule", sa.String(50), nullable=False, server_default="manual"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(50), nullable=True, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_asset_plugin_configs_project", "asset_plugin_configs", ["project_id"])

    op.create_table(
        "asset_sync_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plugin_id", sa.String(20), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assets_found", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_unchanged", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True, server_default=""),
    )
    op.create_index("ix_asset_sync_jobs_project_plugin", "asset_sync_jobs", ["project_id", "plugin_id"])
    op.create_index("ix_asset_sync_jobs_started", "asset_sync_jobs", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_asset_sync_jobs_started", "asset_sync_jobs")
    op.drop_index("ix_asset_sync_jobs_project_plugin", "asset_sync_jobs")
    op.drop_table("asset_sync_jobs")
    op.drop_index("ix_asset_plugin_configs_project", "asset_plugin_configs")
    op.drop_table("asset_plugin_configs")
