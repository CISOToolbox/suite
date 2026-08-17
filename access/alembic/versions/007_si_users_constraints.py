"""tighten si_users constraints + functional index on lower(email)

Revision ID: 007_si_users_constraints
Revises: 006_review_entry_last_login
Create Date: 2026-04-23

Adds:
- CHECK constraint enforcing sync_source IN ('', 'pilot', 'connector')
- Functional index on lower(email) so the personnel-sync webhook's
  WHERE lower(email) = $1 lookup hits an index.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "007_si_users_constraints"
down_revision = "006_review_entry_last_login"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_si_users_sync_source",
        "si_users",
        "sync_source IN ('', 'pilot', 'connector')",
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_si_users_email_lower "
        "ON si_users (lower(email))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_si_users_email_lower")
    op.drop_constraint("ck_si_users_sync_source", "si_users", type_="check")
