"""add last_login_at to si_users

Revision ID: 004_si_users_last_login
Revises: 003_plugin_tables
Create Date: 2026-04-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "004_si_users_last_login"
down_revision = "003_plugin_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "si_users",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("si_users", "last_login_at")
