"""Fix audit_log: rename 'timestamp' to 'logged_at' if table was created
by create_all() before migration 003 ran.

Revision ID: 006_fix_audit_log_column
Revises: 005_add_scan_paths
Create Date: 2026-04-29
"""
from alembic import op
import sqlalchemy as sa

revision = "006_fix_audit_log_column"
down_revision = "005_add_scan_paths"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from sqlalchemy import inspect
    bind = op.get_bind()
    inspector = inspect(bind)
    if "audit_log" not in inspector.get_table_names():
        return
    cols = [c["name"] for c in inspector.get_columns("audit_log")]
    if "timestamp" in cols and "logged_at" not in cols:
        op.alter_column("audit_log", "timestamp", new_column_name="logged_at")


def downgrade() -> None:
    pass
