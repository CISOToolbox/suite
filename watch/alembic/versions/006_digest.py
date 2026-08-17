"""Phase 5: daily digest bookkeeping.

Revision ID: 006_digest
Revises: 005_alert_analysis
Create Date: 2026-05-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "006_digest"
down_revision = "005_alert_analysis"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "digest_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_email", sa.String(320), nullable=False),
        sa.Column(
            "scope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scopes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("calendar_date", sa.String(10), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("alerts_count", sa.Integer, server_default="0"),
        sa.Column("error_message", sa.Text, server_default=""),
        sa.UniqueConstraint("user_email", "scope_id", "calendar_date",
                            name="uq_digest_user_scope_date"),
    )
    op.create_index("ix_digest_runs_user_email", "digest_runs", ["user_email"])
    op.create_index("ix_digest_runs_scope_id", "digest_runs", ["scope_id"])


def downgrade() -> None:
    op.drop_index("ix_digest_runs_scope_id", table_name="digest_runs")
    op.drop_index("ix_digest_runs_user_email", table_name="digest_runs")
    op.drop_table("digest_runs")
