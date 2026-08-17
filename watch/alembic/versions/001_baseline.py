"""Baseline: users, app_settings, audit_log (phase 0 scaffold).

Watch-specific tables (scopes, scope_recipients, watch_targets, alerts,
alert_matches, alert_statuses, alert_analyses, digest_runs, feed_state,
cpe_dict_entries) land in subsequent migrations as each phase adds them.

Revision ID: 001_baseline
Revises:
Create Date: 2026-05-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), unique=True, nullable=False),
        sa.Column("name", sa.String(255), server_default=""),
        sa.Column("picture", sa.String(500), server_default=""),
        sa.Column("provider", sa.String(50), server_default=""),
        sa.Column("provider_id", sa.String(255), server_default=""),
        sa.Column("role", sa.String(20), server_default="user"),
        sa.Column("ai_enabled", sa.String(5), server_default="false"),
        sa.Column("digest_hour", sa.Integer, server_default="7"),
        sa.Column("digest_minute", sa.Integer, server_default="0"),
        sa.Column("digest_timezone", sa.String(64), server_default="Europe/Paris"),
        sa.Column("digest_enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text, server_default=""),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("logged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_email", sa.String(255), server_default=""),
        sa.Column("user_name", sa.String(255), server_default=""),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target", sa.String(500), server_default=""),
        sa.Column("details", sa.Text, server_default=""),
        sa.Column("ip_address", sa.String(64), server_default=""),
    )
    op.create_index("ix_audit_log_logged_at", "audit_log", ["logged_at"])
    op.create_index("ix_audit_log_user", "audit_log", ["user_email"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_user", table_name="audit_log")
    op.drop_index("ix_audit_log_logged_at", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("app_settings")
    op.drop_table("users")
