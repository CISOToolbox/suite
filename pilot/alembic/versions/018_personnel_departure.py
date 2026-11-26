"""a person of the directory has a departure date

Revision ID: 018_personnel_departure
Revises: 017_notification_lang_default
Create Date: 2026-11-26

`personnel.date_depart` (YYYY-MM-DD) is the day an `inactif` person left. It is
broadcast to the modules with the rest of the person, so that a module that
judges access by departure (Compliance GH-04) reads it from the directory.
"""
from alembic import op
import sqlalchemy as sa

revision = "018_personnel_departure"
down_revision = "017_notification_lang_default"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("personnel", sa.Column("date_depart", sa.String(10), nullable=True))


def downgrade() -> None:
    op.drop_column("personnel", "date_depart")
