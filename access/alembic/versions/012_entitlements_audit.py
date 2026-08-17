"""requested entitlements + append-only audit (FEAT-15 Lot 4)

Revision ID: 012_entitlements_audit
Revises: 011_perimeter_type_roles
Create Date: 2026-06-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "012_entitlements_audit"
down_revision = "011_perimeter_type_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "requested_entitlements",
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("id", sa.String(20), primary_key=True),
        sa.Column("si_user_id", sa.String(20), nullable=False),
        sa.Column("perimetre_id", sa.String(20), nullable=False),
        sa.Column("role", sa.Text, nullable=False, server_default=""),
        sa.Column("status", sa.String(30), nullable=False, server_default="demandee"),
        sa.Column("created_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_entitlements_project_user", "requested_entitlements", ["project_id", "si_user_id"])

    op.create_table(
        "entitlement_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("si_user_id", sa.String(20), nullable=False),
        sa.Column("entitlement_id", sa.String(20), nullable=True),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("field", sa.String(50), nullable=False, server_default=""),
        sa.Column("old_value", sa.Text, nullable=False, server_default=""),
        sa.Column("new_value", sa.Text, nullable=False, server_default=""),
        sa.Column("actor", sa.String(255), nullable=False, server_default=""),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_entitlement_audit_project_user", "entitlement_audit", ["project_id", "si_user_id"])


def downgrade() -> None:
    op.drop_index("ix_entitlement_audit_project_user", table_name="entitlement_audit")
    op.drop_table("entitlement_audit")
    op.drop_index("ix_entitlements_project_user", table_name="requested_entitlements")
    op.drop_table("requested_entitlements")
