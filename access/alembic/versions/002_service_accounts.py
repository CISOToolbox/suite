"""add service_accounts table

Revision ID: 002_service_accounts
Revises: 001_baseline
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "002_service_accounts"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("project_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("identifier", sa.String(255), nullable=True, server_default=""),
        sa.Column("platform", sa.String(100), nullable=True, server_default=""),
        sa.Column("application_id", sa.String(20), nullable=True, server_default=""),
        sa.Column("purpose", sa.Text, nullable=True, server_default=""),
        sa.Column("secret_storage", sa.String(50), nullable=True, server_default="unknown"),
        sa.Column("rotation_policy", sa.String(50), nullable=True, server_default="unknown"),
        sa.Column("last_rotation", sa.String(20), nullable=True, server_default=""),
        sa.Column("owners", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("risk_level", sa.String(20), nullable=True, server_default="medium"),
        sa.Column("notes", sa.Text, nullable=True, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.text("NOW()")),
    )
    op.create_index("ix_service_accounts_project", "service_accounts", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_service_accounts_project")
    op.drop_table("service_accounts")
