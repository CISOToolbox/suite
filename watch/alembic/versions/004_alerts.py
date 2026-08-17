"""Phase 3: alerts + matches + per-user statuses + feed bookkeeping.

This migration introduces the four tables that back the ingestion +
matching pipeline:

  * alerts            — one row per CVE/GHSA/CERT-FR advisory.
  * alert_matches     — many-to-many between alerts and watch_targets.
  * alert_statuses    — per-user triage state (new/ack/dismissed…).
  * feed_state        — scheduler bookkeeping (last_sync, cursor…).

Revision ID: 004_alerts
Revises: 003_targets
Create Date: 2026-05-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "004_alerts"
down_revision = "003_targets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("title", sa.String(500), nullable=False, server_default=""),
        sa.Column("summary", sa.Text, server_default=""),
        sa.Column("severity", sa.String(20), server_default="unknown"),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(255), server_default=""),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("kev_listed", sa.Boolean, server_default=sa.text("false"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("references_json", postgresql.JSONB, server_default="[]"),
        sa.Column("affected_json", postgresql.JSONB, server_default="[]"),
        sa.Column("raw_json", postgresql.JSONB, server_default="{}"),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source", "external_id", name="uq_alerts_source_external"),
    )
    op.create_index("ix_alerts_published_at", "alerts", ["published_at"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_kev_listed", "alerts", ["kev_listed"])

    op.create_table(
        "alert_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("watch_targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scopes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("match_kind", sa.String(20), nullable=False),
        sa.Column("match_value", sa.String(500), nullable=False),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_id", "target_id", name="uq_match_alert_target"),
    )
    op.create_index("ix_alert_matches_alert_id", "alert_matches", ["alert_id"])
    op.create_index("ix_alert_matches_target_id", "alert_matches", ["target_id"])
    op.create_index("ix_alert_matches_scope_id", "alert_matches", ["scope_id"])

    op.create_table(
        "alert_statuses",
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="new"),
        sa.Column("note", sa.Text, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "feed_state",
        sa.Column("source", sa.String(50), primary_key=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cursor", sa.String(500), server_default=""),
        sa.Column("last_error", sa.Text, server_default=""),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("items_seen", sa.Integer, server_default="0"),
        sa.Column("items_new", sa.Integer, server_default="0"),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true"), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("feed_state")
    op.drop_table("alert_statuses")
    op.drop_index("ix_alert_matches_scope_id", table_name="alert_matches")
    op.drop_index("ix_alert_matches_target_id", table_name="alert_matches")
    op.drop_index("ix_alert_matches_alert_id", table_name="alert_matches")
    op.drop_table("alert_matches")
    op.drop_index("ix_alerts_kev_listed", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_published_at", table_name="alerts")
    op.drop_table("alerts")
