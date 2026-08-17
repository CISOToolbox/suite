"""Add scan_paths column to applications table.

Revision ID: 005_add_scan_paths
Revises: 004_ignore_rules
Create Date: 2026-04-29
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005_add_scan_paths"
down_revision = "004_ignore_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # Idempotent: skip if column already exists (created by create_all).
    result = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = 'applications' AND column_name = 'scan_paths'"
    ))
    if result.fetchone():
        return
    op.add_column("applications", sa.Column(
        "scan_paths", postgresql.JSONB, server_default="[]",
    ))


def downgrade() -> None:
    op.drop_column("applications", "scan_paths")
