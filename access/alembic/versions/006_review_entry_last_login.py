"""add last_login_at to review_entries

Revision ID: 006_review_entry_last_login
Revises: 005_si_users_sync_source
Create Date: 2026-04-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006_review_entry_last_login"
down_revision = "005_si_users_sync_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "review_entries",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("review_entries", "last_login_at")
