"""add plugin_configs, sync_jobs, sync_snapshots tables

Revision ID: 002_plugin_tables
Revises: 001_baseline
Create Date: 2026-04-17
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "003_plugin_tables"
down_revision = "002_service_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "plugin_configs",
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("plugin_type", sa.String(50), nullable=False),
        sa.Column("label", sa.String(255), nullable=True, server_default=""),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("config_enc", sa.Text, nullable=True, server_default=""),
        sa.Column("group_filters", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("application_id", sa.String(20), nullable=True, server_default=""),
        sa.Column("schedule", sa.String(50), nullable=False, server_default="manual"),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(50), nullable=True, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_plugin_configs_project", "plugin_configs", ["project_id"])

    op.create_table(
        "sync_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plugin_id", sa.String(20), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("users_found", sa.Integer, nullable=False, server_default="0"),
        sa.Column("users_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("users_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("entries_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True, server_default=""),
    )
    op.create_index("ix_sync_jobs_project_plugin", "sync_jobs", ["project_id", "plugin_id"])

    op.create_table(
        "sync_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plugin_id", sa.String(20), nullable=False),
        sa.Column("job_id", UUID(as_uuid=True), nullable=True),
        sa.Column("snapshot_data", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    op.drop_table("sync_snapshots")
    op.drop_index("ix_sync_jobs_project_plugin", table_name="sync_jobs")
    op.drop_table("sync_jobs")
    op.drop_index("ix_plugin_configs_project", table_name="plugin_configs")
    op.drop_table("plugin_configs")
