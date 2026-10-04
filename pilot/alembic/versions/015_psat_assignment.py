"""FEAT-53 — per-user PSAT campaign progress, behind the CSV export.

Revision ID: 015_psat_assignment
Revises: 014_module_prefs
Create Date: 2026-10-04

Snapshot replaced on every PSAT sync: one row per (user, campaign),
excluded users included.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "015_psat_assignment"
down_revision = "014_module_prefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "psat_assignment",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("campaign", sa.String(500), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("last_name", sa.String(255), nullable=False),
        sa.Column("first_name", sa.String(255), nullable=False),
        sa.Column("sent_date", sa.String(10), nullable=False),
        sa.Column("due_date", sa.String(10), nullable=False),
        sa.Column("completion_date", sa.String(10), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("psat_status", sa.String(100), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_psat_assignment_campaign", "psat_assignment",
                    [sa.text("lower(trim(campaign))")])


def downgrade() -> None:
    op.drop_index("ix_psat_assignment_campaign", table_name="psat_assignment")
    op.drop_table("psat_assignment")
