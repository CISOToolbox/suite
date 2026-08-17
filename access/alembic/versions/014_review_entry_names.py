"""add nom/prenom to review_entries (display + name-based SI matching)

Revision ID: 014_review_entry_names
Revises: 013_account_enabled
Create Date: 2026-06-24
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "014_review_entry_names"
down_revision = "013_account_enabled"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("review_entries", sa.Column("nom", sa.String(255), nullable=False, server_default=""))
    op.add_column("review_entries", sa.Column("prenom", sa.String(255), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("review_entries", "prenom")
    op.drop_column("review_entries", "nom")
