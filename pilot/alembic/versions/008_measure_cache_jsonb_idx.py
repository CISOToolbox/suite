"""measure_cache JSONB expression indexes

Revision ID: 008_measure_cache_jsonb_idx
Revises: 007_kpi_tombstone
Create Date: 2026-07-25

The dashboard filters/sorts measure_cache by data->>'due_date' (upcoming
deadlines) and counts by data->>'status' — twice per GET, every 30s per open
tab. Only (module, source_id) was indexed, so both predicates seq-scanned.
Add expression indexes matching the JSONB accessors (and the model's
Index("ix_measure_cache_due_date", data["due_date"].astext) definitions).
"""
from __future__ import annotations

from alembic import op

revision = "008_measure_cache_jsonb_idx"
down_revision = "007_kpi_tombstone"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_measure_cache_due_date "
        "ON measure_cache ((data ->> 'due_date'))"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_measure_cache_status "
        "ON measure_cache ((data ->> 'status'))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_measure_cache_status")
    op.execute("DROP INDEX IF EXISTS ix_measure_cache_due_date")
