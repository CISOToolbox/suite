"""Widen sbom_entries.license column from 100 to 500 chars.

Revision ID: 008_widen_sbom_license
Revises: 007_image_token
Create Date: 2026-04-29
"""
from alembic import op
import sqlalchemy as sa

revision = "008_widen_sbom_license"
down_revision = "007_image_token"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("sbom_entries", "license",
                    type_=sa.String(500),
                    existing_type=sa.String(100))


def downgrade() -> None:
    op.alter_column("sbom_entries", "license",
                    type_=sa.String(100),
                    existing_type=sa.String(500))
