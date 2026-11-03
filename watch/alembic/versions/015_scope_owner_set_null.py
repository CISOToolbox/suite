"""scopes.owner_id -> nullable, ON DELETE SET NULL: a scope survives its owner.

Revision ID: 015_scope_owner_set_null
Revises: 014_alerts_kev_listed_at
Create Date: 2026-11-03

Deleting an account in Pilot removes its Watch `users` row. With CASCADE the
person's scopes went with it, targets and recipients included, while every
other module keeps the owned objects with a null owner. The scope now stays,
ownerless, and Watch administrators manage it (see `src/scope_access.py`).

Downgrade restores the CASCADE but leaves the column nullable: making it NOT
NULL again would mean deleting the scopes that lost their owner meanwhile.
"""
from alembic import op

revision = "015_scope_owner_set_null"
down_revision = "014_alerts_kev_listed_at"
branch_labels = None
depends_on = None

_FK = "scopes_owner_id_fkey"


def upgrade() -> None:
    op.drop_constraint(_FK, "scopes", type_="foreignkey")
    op.alter_column("scopes", "owner_id", nullable=True)
    op.create_foreign_key(_FK, "scopes", "users", ["owner_id"], ["id"],
                          ondelete="SET NULL")


def downgrade() -> None:
    op.drop_constraint(_FK, "scopes", type_="foreignkey")
    op.create_foreign_key(_FK, "scopes", "users", ["owner_id"], ["id"],
                          ondelete="CASCADE")
