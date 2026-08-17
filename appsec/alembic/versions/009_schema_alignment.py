"""Align standalone schema with suite: add missing columns, fix nullability.

Revision ID: 009_schema_alignment
Revises: 008_widen_sbom_license
Create Date: 2026-04-29
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "009_schema_alignment"
down_revision = "008_widen_sbom_license"
branch_labels = None
depends_on = None


def _col_exists(table, column):
    from sqlalchemy import inspect
    bind = op.get_bind()
    cols = [c["name"] for c in inspect(bind).get_columns(table)]
    return column in cols


def upgrade() -> None:
    # -- applications: missing columns --
    if not _col_exists("applications", "ci_api_token"):
        op.add_column("applications", sa.Column(
            "ci_api_token", sa.String(128), server_default=""))
    if not _col_exists("applications", "gate_max_critical"):
        op.add_column("applications", sa.Column(
            "gate_max_critical", sa.Integer, nullable=True))
    if not _col_exists("applications", "gate_max_high"):
        op.add_column("applications", sa.Column(
            "gate_max_high", sa.Integer, nullable=True))
    if not _col_exists("applications", "gate_max_medium"):
        op.add_column("applications", sa.Column(
            "gate_max_medium", sa.Integer, nullable=True))
    if not _col_exists("applications", "webhook_url"):
        op.add_column("applications", sa.Column(
            "webhook_url", sa.String(500), server_default=""))
    if not _col_exists("applications", "notify_on"):
        op.add_column("applications", sa.Column(
            "notify_on", postgresql.JSONB, server_default="[]"))

    # -- findings: missing column --
    if not _col_exists("findings", "is_direct_dependency"):
        op.add_column("findings", sa.Column(
            "is_direct_dependency", sa.Boolean, nullable=True))

    # -- measures.finding_ids: make nullable --
    op.alter_column("measures", "finding_ids",
                    nullable=True,
                    existing_type=postgresql.JSONB)


def downgrade() -> None:
    pass
