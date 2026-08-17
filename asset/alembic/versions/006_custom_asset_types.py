"""add custom_asset_types to project_metadata

Revision ID: 006_custom_asset_types
Revises: 005_drop_unused_nom_index
Create Date: 2026-04-24

Stores user-defined asset types alongside the 8 built-ins. Shape:
[{id: "equipement_reseau", label: "Équipement réseau",
  label_en: "Network equipment", color: "#2563eb"}, ...]

The built-in types are not stored here — they're hardcoded in
Asset_app.js (ASSET_TYPES_BUILTIN). Custom types extend the list at
runtime. Asset.type is a plain VARCHAR so any string value works.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "006_custom_asset_types"
down_revision = "005_drop_unused_nom_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "project_metadata",
        sa.Column("custom_asset_types", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("project_metadata", "custom_asset_types")
