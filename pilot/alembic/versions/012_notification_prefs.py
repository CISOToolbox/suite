"""FEAT-34 — per-user notification prefs + deadline digest runs.

Revision ID: 012_notification_prefs
Revises: 011_measure_group_ref
Create Date: 2026-08-16

Two tables:

* ``notification_prefs`` — one row per Pilot user (opt-in: no row or
  enabled=false means no email). Holds the weekly deadline-digest
  settings from the FEAT-34 spec.
* ``digest_runs`` — send journal, Watch pattern: one row per attempt
  with archived HTML body; the unique (user_id, iso_week) pair makes
  the weekly send idempotent whatever the scheduler tick rate.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "012_notification_prefs"
down_revision = "011_measure_group_ref"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_prefs",
        sa.Column("user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("day_of_week", sa.SmallInteger, nullable=False, server_default="0"),  # 0=lundi … 6=dimanche
        sa.Column("upcoming_days", sa.SmallInteger, nullable=False, server_default="14"),
        sa.Column("include_overdue", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("scope", sa.String(10), nullable=False, server_default="mine"),  # mine | all
        sa.Column("modules", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),  # [] = tous
        sa.Column("lang", sa.String(5), nullable=False, server_default="fr"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_table(
        "digest_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("iso_week", sa.String(10), nullable=False),  # "2026-W34" ("test" runs use a uuid suffix)
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("status", sa.String(20), nullable=False),  # sent | failed | skipped_empty
        sa.Column("items_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=False, server_default=""),
        sa.Column("body_html", sa.Text, nullable=False, server_default=""),
    )
    op.create_index("uq_digest_runs_user_week", "digest_runs",
                    ["user_id", "iso_week"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_digest_runs_user_week", table_name="digest_runs")
    op.drop_table("digest_runs")
    op.drop_table("notification_prefs")
