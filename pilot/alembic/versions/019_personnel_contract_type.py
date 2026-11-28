"""a person's contract type is distinct from their status

Revision ID: 019_personnel_contract_type
Revises: 018_personnel_departure
Create Date: 2026-11-26

`personnel.statut` is the activity (recrutement, actif, inactif) and the new
`personnel.type_contrat` the contract (interne, externe, alternant,
stagiaire). A person stored `externe` becomes `actif` with the contract
`externe`. Every other person's contract stays empty — not said in Pilot —
so that a module which already knows it (Access) keeps it until it is
entered here. Statuses an earlier CSV import stored in English are read.
"""
from alembic import op
import sqlalchemy as sa

revision = "019_personnel_contract_type"
down_revision = "018_personnel_departure"
branch_labels = None
depends_on = None

_WORDS = {"active": "actif", "inactive": "inactif", "left": "inactif", "recruiting": "recrutement"}


def upgrade() -> None:
    op.add_column("personnel", sa.Column("type_contrat", sa.String(20), nullable=False, server_default=sa.text("''")))
    op.execute("UPDATE personnel SET statut = 'actif', type_contrat = 'externe' WHERE lower(trim(statut)) = 'externe'")
    op.execute("UPDATE personnel SET statut = lower(trim(statut)) WHERE statut <> lower(trim(statut))")
    for word, statut in _WORDS.items():
        op.execute(sa.text("UPDATE personnel SET statut = :s WHERE statut = :w").bindparams(s=statut, w=word))


def downgrade() -> None:
    op.execute("UPDATE personnel SET statut = 'externe' WHERE type_contrat = 'externe' AND statut = 'actif'")
    op.drop_column("personnel", "type_contrat")
