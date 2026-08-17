"""measure progress journal (FEAT-12)

Revision ID: 015_measure_progress_log
Revises: 014_review_entry_names
Create Date: 2026-06-29

Adds a timestamped progress journal (progress_log JSONB, list of {at,by,text})
to measures so a responsible can document where remediation stands, distinct
from the discrete statut.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "015_measure_progress_log"
down_revision = "014_review_entry_names"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "measures",
        sa.Column("progress_log", postgresql.JSONB(astext_type=sa.Text()),
                  nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("measures", "progress_log")
