"""applications: type + roles (perimeters, FEAT-15 Lot 2)

Revision ID: 011_perimeter_type_roles
Revises: 010_si_users_referential
Create Date: 2026-06-22

UI-only rename of "applications" to "périmètres": the table/model/id stay
`applications`/`APP-`. This migration only adds two columns:
- type  : application | infrastructure | physique (default 'application')
- roles : JSONB list of free-text role names for this perimeter

No rename, no FK change. Existing rows default to type='application', roles=[].
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "011_perimeter_type_roles"
down_revision = "010_si_users_referential"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("type", sa.String(20), nullable=False, server_default="application"))
    op.add_column("applications", sa.Column("roles", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")))


def downgrade() -> None:
    op.drop_column("applications", "roles")
    op.drop_column("applications", "type")
