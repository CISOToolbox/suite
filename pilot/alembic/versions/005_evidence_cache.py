"""consolidated evidence cache (FEAT-08)

Revision ID: 005_evidence_cache
Revises: 004_personnel_sync_source
Create Date: 2026-06-29

Twin of measure_cache: holds the cross-module evidence/proof registry fed by
each module's GET /api/internal/evidences (pull) and /api/evidences/notify
(push). Also created by Base.metadata.create_all at startup; this migration
tracks it for existing deployments.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "005_evidence_cache"
down_revision = "004_personnel_sync_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_cache",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("module", sa.String(length=50), nullable=False),
        sa.Column("source_id", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=100), nullable=True),
        sa.Column("entity_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("data", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("synced_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.UniqueConstraint("module", "source_id", name="uq_evidence_cache_module_source"),
    )
    op.create_index("ix_evidence_cache_module_source", "evidence_cache", ["module", "source_id"])


def downgrade() -> None:
    op.drop_index("ix_evidence_cache_module_source", table_name="evidence_cache")
    op.drop_table("evidence_cache")
