"""add last_login_at to assets

Revision ID: 002_assets_last_login
Revises: 001_baseline
Create Date: 2026-04-23
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "002_assets_last_login"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "last_login_at")
