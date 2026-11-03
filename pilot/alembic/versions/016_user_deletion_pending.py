"""An unfinished account deletion stays visible, and can be retried.

Revision ID: 016_user_deletion_pending
Revises: 015_psat_assignment
Create Date: 2026-11-03

Deleting an account removed the Pilot row even when a module had not
confirmed its own deletion: the module kept the person's row, nothing in
Pilot showed it any more, and the next holder of the address inherited it.
The row now stays until every module has confirmed, unable to sign in.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "016_user_deletion_pending"
down_revision = "015_psat_assignment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("deletion_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("deletion_report", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("users", "deletion_report")
    op.drop_column("users", "deletion_requested_at")
