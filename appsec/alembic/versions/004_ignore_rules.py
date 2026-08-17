"""add ignore_rules table (v2: multi-app + multi-criteria)

Revision ID: 004_ignore_rules
Revises: 003_audit_log
Create Date: 2026-04-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "004_ignore_rules"
down_revision = "003_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ignore_rules CASCADE")
    op.create_table(
        "ignore_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("application_ids", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("criteria", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_by", sa.String(255), nullable=True, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_ignore_rules_enabled", "ignore_rules", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_ignore_rules_enabled")
    op.drop_table("ignore_rules")
