"""add account_enabled to si_users and review_entries

Revision ID: 013_account_enabled
Revises: 012_entitlements_audit
Create Date: 2026-06-23
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "013_account_enabled"
down_revision = "012_entitlements_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("si_users", sa.Column("account_enabled", sa.Boolean(), nullable=True))
    op.add_column("review_entries", sa.Column("account_enabled", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("review_entries", "account_enabled")
    op.drop_column("si_users", "account_enabled")
