"""Phase 2: watch_targets — technologies monitored inside a scope.

Three identification kinds: cpe (NVD), purl (OSV/GHSA), keyword (CERT-FR
and other free-text advisories).

Revision ID: 003_targets
Revises: 002_scopes
Create Date: 2026-05-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003_targets"
down_revision = "002_scopes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "watch_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scopes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("label", sa.String(200), server_default=""),
        sa.Column("version_constraint", sa.String(100), server_default=""),
        sa.Column("notes", sa.Text, server_default=""),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scope_id", "kind", "value", name="uq_targets_scope_kind_value"),
    )
    op.create_index("ix_watch_targets_scope_id", "watch_targets", ["scope_id"])
    op.create_index("ix_watch_targets_kind", "watch_targets", ["kind"])


def downgrade() -> None:
    op.drop_index("ix_watch_targets_kind", table_name="watch_targets")
    op.drop_index("ix_watch_targets_scope_id", table_name="watch_targets")
    op.drop_table("watch_targets")
