"""FEAT-42 — service-account expiry date + application owner email.

Revision ID: 019_sa_expiration_app_owner
Revises: 018_owner_set_null
Create Date: 2026-09-05

Two additive columns:
- service_accounts.date_expiration (ISO date string, '' = no expiry) — drives
  the J-30/15/7/1 owner alerts built by src/expiry_notifier.py.
- applications.owner_email — the application/perimeter owner, primary
  recipient of those alerts (reviewers are the fallback).
"""
from alembic import op
import sqlalchemy as sa

revision = "019_sa_expiration_app_owner"
down_revision = "018_owner_set_null"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("service_accounts",
                  sa.Column("date_expiration", sa.String(20), nullable=True,
                            server_default=""))
    op.add_column("applications",
                  sa.Column("owner_email", sa.String(255), nullable=False,
                            server_default=""))


def downgrade() -> None:
    op.drop_column("service_accounts", "date_expiration")
    op.drop_column("applications", "owner_email")
