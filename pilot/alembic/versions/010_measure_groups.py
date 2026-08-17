"""measure_groups + measure_group_members (FEAT-11 meta-measures)

Revision ID: 010_measure_groups
Revises: 009_drop_project_shared_with
Create Date: 2026-08-15

A meta-measure groups N MeasureCache rows steered as one: canonical
status/due_date/responsible live on the group and propagate to the
source modules via the existing write-back. UniqueConstraint(measure_id)
enforces the one-group-per-measure invariant. Tables are also created by
Base.metadata.create_all on fresh databases; this migration tracks the
change for existing deployments.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "010_measure_groups"
down_revision = "009_drop_project_shared_with"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "measure_groups",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("title", sa.String(500), nullable=False, server_default=sa.text("''")),
        sa.Column("status", sa.String(30), nullable=False, server_default=sa.text("'planned'")),
        sa.Column("due_date", sa.String(20), nullable=True, server_default=sa.text("''")),
        sa.Column("responsible", sa.String(255), nullable=True, server_default=sa.text("''")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_table(
        "measure_group_members",
        sa.Column("group_id", UUID(as_uuid=True),
                  sa.ForeignKey("measure_groups.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("measure_id", UUID(as_uuid=True),
                  sa.ForeignKey("measure_cache.id", ondelete="CASCADE"), primary_key=True),
        sa.UniqueConstraint("measure_id", name="uq_measure_group_member"),
    )


def downgrade() -> None:
    op.drop_table("measure_group_members")
    op.drop_table("measure_groups")
