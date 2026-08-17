"""Add personnel.sync_source.

Provenance of a directory entry: "" = managed in Pilot (editable), "access" =
fed from Access (where an HR connector lives). "access" rows are read-only in
Pilot and never pushed back to Access (one-directional sync, no loop).

Idempotent: only adds the column if absent.

Revision ID: 004_personnel_sync_source
Revises: 003_connector_rename
Create Date: 2026-06-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "004_personnel_sync_source"
down_revision = "003_connector_rename"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(sa.text(
        "ALTER TABLE personnel ADD COLUMN IF NOT EXISTS sync_source "
        "VARCHAR(20) NOT NULL DEFAULT ''"
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text(
        "ALTER TABLE personnel DROP COLUMN IF EXISTS sync_source"
    ))
