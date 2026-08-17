"""Digest v2 — threat topic watch (theme-based monitoring).

Revision ID: 009_threat_topics
Revises: 008_digest_v2
Create Date: 2026-05-13

Adds two tables to support the "veille menaces" half of the digest:

  * ``threat_topics``   — themes the recipient cares about, e.g.
                          "Python supply chain" → ["pypi", "typosquatting",
                          "malicious package"]. Owned by a Scope so each
                          scope can have a distinct watchlist.
  * ``threat_matches``  — many-to-many bridge: which Alert hit which
                          ThreatTopic, with the matched terms preserved
                          for transparency in the digest (so the user
                          sees *which* keyword triggered the inclusion).

Both tables cascade on Scope / Alert / ThreatTopic deletion so a
deleted topic immediately stops contributing to digests.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "009_threat_topics"
down_revision = "008_digest_v2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_topics",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scopes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("keywords", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scope_id", "label", name="uq_threat_topics_scope_label"),
    )
    op.create_index("ix_threat_topics_scope_id", "threat_topics", ["scope_id"])

    op.create_table(
        "threat_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "topic_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_topics.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scopes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("match_terms", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_id", "topic_id", name="uq_threat_matches_alert_topic"),
    )
    op.create_index("ix_threat_matches_scope_id", "threat_matches", ["scope_id"])
    op.create_index("ix_threat_matches_alert_id", "threat_matches", ["alert_id"])
    op.create_index("ix_threat_matches_matched_at", "threat_matches", ["matched_at"])


def downgrade() -> None:
    op.drop_index("ix_threat_matches_matched_at", table_name="threat_matches")
    op.drop_index("ix_threat_matches_alert_id", table_name="threat_matches")
    op.drop_index("ix_threat_matches_scope_id", table_name="threat_matches")
    op.drop_table("threat_matches")

    op.drop_index("ix_threat_topics_scope_id", table_name="threat_topics")
    op.drop_table("threat_topics")
