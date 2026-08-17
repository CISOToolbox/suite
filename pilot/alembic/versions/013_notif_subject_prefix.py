"""FEAT-34 follow-up — per-user email subject prefix.

Revision ID: 013_notif_subject_prefix
Revises: 012_notification_prefs
Create Date: 2026-08-16

Lets each user tag their digest emails for mailbox filtering; the
default keeps the historical "[CISO Toolbox]".
"""
from alembic import op
import sqlalchemy as sa

revision = "013_notif_subject_prefix"
down_revision = "012_notification_prefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("notification_prefs",
                  sa.Column("subject_prefix", sa.String(60), nullable=False,
                            server_default="[CISO Toolbox]"))


def downgrade() -> None:
    op.drop_column("notification_prefs", "subject_prefix")
