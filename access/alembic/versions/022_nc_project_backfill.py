"""Backfill the register's project from the subject (FEAT-45)

Revision ID: 022_nc_project_backfill
Revises: 021_nonconformity_project
Create Date: 2026-09-21

A review entry is keyed `<project>:<review>:<entry>`, so the records that
already point at one tell which project they belong to. Records with no
subject keep no project: they stay module-level, as the console's do.
"""
from alembic import op

revision = "022_nc_project_backfill"
down_revision = "021_nonconformity_project"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("nonconformities", "derogations"):
        op.execute(
            f"UPDATE {table} SET project_id = split_part(subject_id, ':', 1) "
            "WHERE (project_id IS NULL OR project_id = '') "
            "AND subject_type = 'review_entry' AND subject_id LIKE '%:%:%'"
        )


def downgrade() -> None:
    """The backfill is not undone: the column itself goes with 021."""
