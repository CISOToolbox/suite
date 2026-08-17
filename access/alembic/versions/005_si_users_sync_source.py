"""add sync_source to si_users

Revision ID: 005_si_users_sync_source
Revises: 004_si_users_last_login
Create Date: 2026-04-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "005_si_users_sync_source"
down_revision = "004_si_users_last_login"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "si_users",
        sa.Column("sync_source", sa.String(length=20), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("si_users", "sync_source")
