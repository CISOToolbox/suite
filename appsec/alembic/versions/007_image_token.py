"""Add image_token_encrypted column for registry auth.

Revision ID: 007_image_token
Revises: 006_fix_audit_log_column
Create Date: 2026-04-29
"""
from alembic import op
import sqlalchemy as sa

revision = "007_image_token"
down_revision = "006_fix_audit_log_column"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    result = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = 'applications' AND column_name = 'image_token_encrypted'"
    ))
    if result.fetchone():
        return
    op.add_column("applications", sa.Column(
        "image_token_encrypted", sa.Text, server_default="",
    ))


def downgrade() -> None:
    op.drop_column("applications", "image_token_encrypted")
