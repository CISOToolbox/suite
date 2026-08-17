"""user type + uniform compliance proofs

Revision ID: 008_user_type_proofs
Revises: 007_si_users_constraints
Create Date: 2026-04-24

Changes:
- Add type_compte (salarie / prestataire / stagiaire / alternant)
- Add justification TEXT fields for every proof
- Convert background_check from URL-only to the same shape as other
  proofs (boolean + date + justification). The legacy URL field is kept
  under background_check_url for backwards compatibility and can be
  migrated by the operator to the new background_check_justification
  field if desired.
- Add nda_signed + nda_date + nda_justification (for prestataires).
- Rename the legacy statut='employe' to 'actif' to match Pilot.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "008_user_type_proofs"
down_revision = "007_si_users_constraints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # type_compte with a CHECK constraint so connectors can't push garbage.
    op.add_column("si_users",
        sa.Column("type_compte", sa.String(50), nullable=False, server_default="salarie"))
    op.execute(
        "ALTER TABLE si_users ADD CONSTRAINT ck_si_users_type_compte "
        "CHECK (type_compte IN ('salarie', 'prestataire', 'stagiaire', 'alternant'))"
    )

    # Justification fields for existing proofs.
    op.add_column("si_users", sa.Column("politique_justification",       sa.Text, nullable=False, server_default=""))
    op.add_column("si_users", sa.Column("mfa_justification",              sa.Text, nullable=False, server_default=""))
    op.add_column("si_users", sa.Column("sensibilisation_justification", sa.Text, nullable=False, server_default=""))

    # Background-check promoted to a full proof (bool + date + justification).
    # Existing background_check_url is preserved for legacy reads.
    op.add_column("si_users", sa.Column("background_check",               sa.Boolean, nullable=False, server_default=sa.text("false")))
    op.add_column("si_users", sa.Column("background_check_date",          sa.String(20), nullable=False, server_default=""))
    op.add_column("si_users", sa.Column("background_check_justification", sa.Text, nullable=False, server_default=""))

    # NDA (mandatory for prestataires, optional for others).
    op.add_column("si_users", sa.Column("nda_signed",        sa.Boolean, nullable=False, server_default=sa.text("false")))
    op.add_column("si_users", sa.Column("nda_date",          sa.String(20), nullable=False, server_default=""))
    op.add_column("si_users", sa.Column("nda_justification", sa.Text, nullable=False, server_default=""))

    # Migrate existing statut values. Two legacy quirks:
    #   1. 'employe' (old label) → 'actif' (Pilot-aligned)
    #   2. 'prestataire' used to live on the statut column — split it out
    #      into the new type_compte column and normalise statut to 'actif'.
    op.execute("UPDATE si_users SET statut = 'actif' WHERE statut = 'employe'")
    op.execute(
        "UPDATE si_users SET type_compte = 'prestataire', statut = 'actif' "
        "WHERE statut = 'prestataire'"
    )
    # Defensive: coerce any remaining unexpected value to 'actif' to
    # avoid blocking the CHECK constraint below on legacy / test data.
    op.execute(
        "UPDATE si_users SET statut = 'actif' "
        "WHERE statut NOT IN ('actif', 'ancien', 'recrutement')"
    )

    # Enforce the new statut enum so historical junk can't survive.
    op.execute(
        "ALTER TABLE si_users ADD CONSTRAINT ck_si_users_statut "
        "CHECK (statut IN ('actif', 'ancien', 'recrutement'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE si_users DROP CONSTRAINT IF EXISTS ck_si_users_statut")
    op.execute("UPDATE si_users SET statut = 'employe' WHERE statut = 'actif'")

    op.drop_column("si_users", "nda_justification")
    op.drop_column("si_users", "nda_date")
    op.drop_column("si_users", "nda_signed")

    op.drop_column("si_users", "background_check_justification")
    op.drop_column("si_users", "background_check_date")
    op.drop_column("si_users", "background_check")

    op.drop_column("si_users", "sensibilisation_justification")
    op.drop_column("si_users", "mfa_justification")
    op.drop_column("si_users", "politique_justification")

    op.execute("ALTER TABLE si_users DROP CONSTRAINT IF EXISTS ck_si_users_type_compte")
    op.drop_column("si_users", "type_compte")
