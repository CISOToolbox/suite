"""Phase 1: scopes + scope_recipients.

Each user owns scopes (logical groupings of monitored technologies); a
scope's daily digest is sent to email-keyed recipients. Recipients are
not FK'd to users.id on purpose so they can be pre-provisioned before
their first Watch login.

Revision ID: 002_scopes
Revises: 001_baseline
Create Date: 2026-05-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_scopes"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "owner_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scopes_owner_id", "scopes", ["owner_id"])

    op.create_table(
        "scope_recipients",
        sa.Column(
            "scope_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scopes.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("email", sa.String(320), primary_key=True),
        sa.Column("name", sa.String(255), server_default=""),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("added_by_email", sa.String(320), server_default=""),
    )
    op.create_index("ix_scope_recipients_email", "scope_recipients", ["email"])


def downgrade() -> None:
    op.drop_index("ix_scope_recipients_email", table_name="scope_recipients")
    op.drop_table("scope_recipients")
    op.drop_index("ix_scopes_owner_id", table_name="scopes")
    op.drop_table("scopes")
