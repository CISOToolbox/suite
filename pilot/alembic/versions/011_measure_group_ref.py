"""Give meta-measures a human ref (META-NNN).

Revision ID: 011_measure_group_ref
Revises: 010_measure_groups
Create Date: 2026-08-16

The measures table showed a member-count badge where every other row
shows its FEAT-32 ref (MES-NNN…) — a meta-measure needs a citable id
of its own. Sequential META-NNN, assigned at creation, backfilled here
in created_at order.
"""
from alembic import op
import sqlalchemy as sa

revision = "011_measure_group_ref"
down_revision = "010_measure_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("measure_groups", sa.Column("ref", sa.String(20), nullable=False, server_default=""))
    op.execute("""
        UPDATE measure_groups g SET ref = 'META-' || LPAD(n.rn::text, 3, '0')
        FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY created_at, id) AS rn
              FROM measure_groups) n
        WHERE n.id = g.id
    """)
    op.create_index("uq_measure_groups_ref", "measure_groups", ["ref"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_measure_groups_ref", table_name="measure_groups")
    op.drop_column("measure_groups", "ref")
