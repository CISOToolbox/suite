"""Phase 4: LLM-generated alert analyses (cache by content hash).

Revision ID: 005_alert_analysis
Revises: 004_alerts
Create Date: 2026-05-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005_alert_analysis"
down_revision = "004_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_analyses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("sections", postgresql.JSONB, server_default="{}"),
        sa.Column("provider", sa.String(50), server_default=""),
        sa.Column("model", sa.String(100), server_default=""),
        sa.Column("generated_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_id", "content_hash", name="uq_analysis_alert_hash"),
    )
    op.create_index("ix_alert_analyses_alert_id", "alert_analyses", ["alert_id"])


def downgrade() -> None:
    op.drop_index("ix_alert_analyses_alert_id", table_name="alert_analyses")
    op.drop_table("alert_analyses")
