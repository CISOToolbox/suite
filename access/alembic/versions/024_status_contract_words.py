"""a user's status and contract type in Pilot's words (FEAT-74)

Revision ID: 024_status_contract_words
Revises: 023_derogation_revoked_by
Create Date: 2026-11-26

The activity and the contract are two notions, named alike in Pilot,
Compliance and Access: statut recrutement | actif | inactif (`ancien`
becomes `inactif`), type_compte interne | externe | alternant | stagiaire
(`salarie` becomes `interne`, `prestataire` becomes `externe`).
"""
from alembic import op

revision = "024_status_contract_words"
down_revision = "023_derogation_revoked_by"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE si_users DROP CONSTRAINT IF EXISTS ck_si_users_statut")
    op.execute("ALTER TABLE si_users DROP CONSTRAINT IF EXISTS ck_si_users_type_compte")
    op.execute("UPDATE si_users SET statut = 'inactif' WHERE statut = 'ancien'")
    op.execute("UPDATE si_users SET type_compte = 'interne' WHERE type_compte = 'salarie'")
    op.execute("UPDATE si_users SET type_compte = 'externe' WHERE type_compte = 'prestataire'")
    op.execute("ALTER TABLE si_users ALTER COLUMN type_compte SET DEFAULT 'interne'")
    op.execute("ALTER TABLE si_users ADD CONSTRAINT ck_si_users_statut "
               "CHECK (statut IN ('recrutement', 'actif', 'inactif'))")
    op.execute("ALTER TABLE si_users ADD CONSTRAINT ck_si_users_type_compte "
               "CHECK (type_compte IN ('interne', 'externe', 'alternant', 'stagiaire'))")


def downgrade() -> None:
    op.execute("ALTER TABLE si_users DROP CONSTRAINT IF EXISTS ck_si_users_statut")
    op.execute("ALTER TABLE si_users DROP CONSTRAINT IF EXISTS ck_si_users_type_compte")
    op.execute("UPDATE si_users SET statut = 'ancien' WHERE statut = 'inactif'")
    op.execute("UPDATE si_users SET type_compte = 'salarie' WHERE type_compte = 'interne'")
    op.execute("UPDATE si_users SET type_compte = 'prestataire' WHERE type_compte = 'externe'")
    op.execute("ALTER TABLE si_users ALTER COLUMN type_compte SET DEFAULT 'salarie'")
    op.execute("ALTER TABLE si_users ADD CONSTRAINT ck_si_users_statut "
               "CHECK (statut IN ('actif', 'ancien', 'recrutement'))")
    op.execute("ALTER TABLE si_users ADD CONSTRAINT ck_si_users_type_compte "
               "CHECK (type_compte IN ('salarie', 'prestataire', 'stagiaire', 'alternant'))")
