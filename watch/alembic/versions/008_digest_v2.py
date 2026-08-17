"""Digest v2: per-scope severity thresholds + multi-language analysis cache.

Revision ID: 008_digest_v2
Revises: 007_per_scope_digest
Create Date: 2026-05-13

Adds four nullable/defaulted columns to ``scopes`` for the redesigned
critical-vulnerability digest:

  * ``digest_severity_min``  — minimum severity to include (default 'critical')
  * ``digest_include_kev``   — always include KEV-listed (bypasses severity floor)
  * ``digest_cvss_min``      — optional CVSS floor (None disables)
  * ``digest_epss_min``      — optional EPSS floor (None disables)

Extends ``alert_analyses`` with a ``language`` column so the same alert
can hold one cached analysis per requested locale. The uniqueness key
moves from (alert_id, content_hash) to (alert_id, content_hash,
language). Existing rows default to 'en' so the Phase 4 UI flow keeps
hitting its cache unchanged.
"""
from alembic import op
import sqlalchemy as sa


revision = "008_digest_v2"
down_revision = "007_per_scope_digest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Scope-level digest filter thresholds.
    op.add_column("scopes",
        sa.Column("digest_severity_min", sa.String(20),
                  nullable=False, server_default=sa.text("'critical'")))
    op.add_column("scopes",
        sa.Column("digest_include_kev", sa.Boolean,
                  nullable=False, server_default=sa.text("true")))
    op.add_column("scopes",
        sa.Column("digest_cvss_min", sa.Float, nullable=True))
    op.add_column("scopes",
        sa.Column("digest_epss_min", sa.Float, nullable=True))

    # Multi-language cache key for alert analyses.
    op.add_column("alert_analyses",
        sa.Column("language", sa.String(8),
                  nullable=False, server_default=sa.text("'en'")))
    op.drop_constraint("uq_analysis_alert_hash", "alert_analyses", type_="unique")
    op.create_unique_constraint(
        "uq_analysis_alert_hash_lang",
        "alert_analyses",
        ["alert_id", "content_hash", "language"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_analysis_alert_hash_lang", "alert_analyses", type_="unique")
    op.create_unique_constraint(
        "uq_analysis_alert_hash", "alert_analyses",
        ["alert_id", "content_hash"],
    )
    op.drop_column("alert_analyses", "language")

    op.drop_column("scopes", "digest_epss_min")
    op.drop_column("scopes", "digest_cvss_min")
    op.drop_column("scopes", "digest_include_kev")
    op.drop_column("scopes", "digest_severity_min")
