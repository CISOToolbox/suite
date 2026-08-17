"""si_users: equipe + date_fin_contrat + manager_email (FEAT-15 Lot 1)

Revision ID: 010_si_users_referential
Revises: 009_canonical_project
Create Date: 2026-06-22

Adds three identity-referential fields to si_users:
- equipe            : team / department (free text, all user types)
- date_fin_contrat  : planned contract end date (ISO string). Required at the
                      HTTP layer for every type_compte except 'salarie'.
- manager_email     : email of the user's manager (hierarchy), used to
                      authorize edits of the user's requested entitlements.

Column-add only — no rename, no FK change. Existing rows default to "".
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "010_si_users_referential"
down_revision = "009_canonical_project"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("si_users", sa.Column("equipe", sa.String(255), nullable=False, server_default=""))
    op.add_column("si_users", sa.Column("date_fin_contrat", sa.String(20), nullable=False, server_default=""))
    op.add_column("si_users", sa.Column("manager_email", sa.String(255), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("si_users", "manager_email")
    op.drop_column("si_users", "date_fin_contrat")
    op.drop_column("si_users", "equipe")
