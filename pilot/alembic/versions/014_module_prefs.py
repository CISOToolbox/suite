"""FEAT-35 — per-module notification preferences.

Revision ID: 014_module_prefs
Revises: 013_notif_subject_prefix
Create Date: 2026-08-17

One JSONB column instead of per-module columns so future modules add
their preference blocks without another migration. Shape:
    {"appsec": {"alert_enabled": true, "alert_min_severity": "low",
                "weekly_enabled": true, "weekly_day": 0,
                "weekly_min_severity": "low"}}
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "014_module_prefs"
down_revision = "013_notif_subject_prefix"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("notification_prefs",
                  sa.Column("module_prefs", JSONB, nullable=False,
                            server_default=sa.text("'{}'::jsonb")))


def downgrade() -> None:
    op.drop_column("notification_prefs", "module_prefs")
