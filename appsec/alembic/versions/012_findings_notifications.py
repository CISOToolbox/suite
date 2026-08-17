"""FEAT-35 — findings email notifications.

Revision ID: 012_findings_notifications
Revises: 011_measure_progress_log
Create Date: 2026-08-17

* ``applications.notification_emails`` — WHO gets notified about this app
  (free emails, chips in the app config modal; [] = silence).
* ``applications.notification_lang`` — email language for recipients
  without a suite account (account holders get their own prefs language).
* ``digest_runs`` — send journal (Watch/Pilot pattern): one row per
  attempt with archived HTML body. ``kind`` is ``alert`` (per scan) or
  ``weekly``; the unique (recipient, kind, period_key) makes both sends
  idempotent — period_key is the scan job id or the ISO week.
* ``notification_prefs`` — LOCAL per-user preferences for standalone
  deployments only; in suite mode AppSec proxies Pilot's storage.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "012_findings_notifications"
down_revision = "011_measure_progress_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications",
                  sa.Column("notification_emails", JSONB, nullable=False,
                            server_default=sa.text("'[]'::jsonb")))
    op.add_column("applications",
                  sa.Column("notification_lang", sa.String(5), nullable=False,
                            server_default="en"))
    op.create_table(
        "digest_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("recipient", sa.String(320), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),  # alert | weekly
        sa.Column("period_key", sa.String(64), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("status", sa.String(20), nullable=False),  # sent | failed | skipped_empty
        sa.Column("items_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=False, server_default=""),
        sa.Column("body_html", sa.Text, nullable=False, server_default=""),
    )
    op.create_index("uq_digest_runs_recipient_period", "digest_runs",
                    ["recipient", "kind", "period_key"], unique=True)
    op.create_table(
        "notification_prefs",
        sa.Column("user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("lang", sa.String(5), nullable=False, server_default="fr"),
        sa.Column("module_prefs", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    op.drop_table("notification_prefs")
    op.drop_index("uq_digest_runs_recipient_period", table_name="digest_runs")
    op.drop_table("digest_runs")
    op.drop_column("applications", "notification_lang")
    op.drop_column("applications", "notification_emails")
