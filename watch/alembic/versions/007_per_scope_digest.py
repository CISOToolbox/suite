"""Move digest preferences from users to scopes (Option A — per-scope).

Revision ID: 007_per_scope_digest
Revises: 006_digest
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa


revision = "007_per_scope_digest"
down_revision = "006_digest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Scopes gain their own digest preferences.
    op.add_column("scopes",
        sa.Column("digest_enabled", sa.Boolean, nullable=False, server_default=sa.text("true")))
    op.add_column("scopes",
        sa.Column("digest_hour", sa.Integer, nullable=False, server_default=sa.text("7")))
    op.add_column("scopes",
        sa.Column("digest_minute", sa.Integer, nullable=False, server_default=sa.text("0")))
    op.add_column("scopes",
        sa.Column("digest_timezone", sa.String(64), nullable=False, server_default=sa.text("'Europe/Paris'")))

    # Users lose them.
    op.drop_column("users", "digest_enabled")
    op.drop_column("users", "digest_hour")
    op.drop_column("users", "digest_minute")
    op.drop_column("users", "digest_timezone")


def downgrade() -> None:
    op.add_column("users",
        sa.Column("digest_enabled", sa.Boolean, nullable=False, server_default=sa.text("true")))
    op.add_column("users",
        sa.Column("digest_hour", sa.Integer, nullable=False, server_default=sa.text("7")))
    op.add_column("users",
        sa.Column("digest_minute", sa.Integer, nullable=False, server_default=sa.text("0")))
    op.add_column("users",
        sa.Column("digest_timezone", sa.String(64), nullable=False, server_default=sa.text("'Europe/Paris'")))

    op.drop_column("scopes", "digest_timezone")
    op.drop_column("scopes", "digest_minute")
    op.drop_column("scopes", "digest_hour")
    op.drop_column("scopes", "digest_enabled")
