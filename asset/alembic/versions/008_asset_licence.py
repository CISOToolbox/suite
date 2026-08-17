"""add licence (renewal cycle) JSONB to assets

Revision ID: 008_asset_licence
Revises: 007_canonical_project
Create Date: 2026-06-08

License / support contract cycle carried on each asset:
  licence = {date_renouvellement, preavis_jours, cout, devise,
             reference, contact}
Drives the "Échéances" view and the renewal email alert. The whole
sub-object round-trips through the project blob (projects.py
_decompose_data / _asset_to_dict).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "008_asset_licence"
down_revision = "007_canonical_project"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("licence", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("assets", "licence")
