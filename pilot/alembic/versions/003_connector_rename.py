"""Rename m365_* AppSettings keys to the connector_<id>_<field> convention.

Background: the M365 connector originally stored its credentials under
ad-hoc keys (``m365_tenant_id``, ``m365_client_id``, ``m365_client_secret``).
The centralized connectors framework introduced by
``docs/CHANTIER_CONNECTEURS.md`` standardises every connector key as
``connector_<connector_id>_<field_id>`` so a generic loader can iterate
schema fields without hardcoded prefixes.

This migration is **lossless**: it renames the three keys in place if
they exist. Rows for missing keys are silently skipped. The downgrade is
exactly symmetric.

Revision ID: 003_connector_rename
Revises: 002_kpi
Create Date: 2026-05-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "003_connector_rename"
down_revision = "002_kpi"
branch_labels = None
depends_on = None


_RENAMES = [
    ("m365_tenant_id",     "connector_m365_tenant_id"),
    ("m365_client_id",     "connector_m365_client_id"),
    ("m365_client_secret", "connector_m365_client_secret"),
]


def upgrade() -> None:
    conn = op.get_bind()
    for old, new in _RENAMES:
        # If the new key already exists (re-run safety), leave the existing
        # value alone and just drop the old one.
        conn.execute(
            sa.text(
                "DELETE FROM app_settings "
                "WHERE key = :old AND EXISTS ("
                "  SELECT 1 FROM app_settings WHERE key = :new)"
            ),
            {"old": old, "new": new},
        )
        conn.execute(
            sa.text("UPDATE app_settings SET key = :new WHERE key = :old"),
            {"old": old, "new": new},
        )


def downgrade() -> None:
    conn = op.get_bind()
    for old, new in _RENAMES:
        # Symmetric: keep the legacy key value if both exist.
        conn.execute(
            sa.text(
                "DELETE FROM app_settings "
                "WHERE key = :new AND EXISTS ("
                "  SELECT 1 FROM app_settings WHERE key = :old)"
            ),
            {"old": old, "new": new},
        )
        conn.execute(
            sa.text("UPDATE app_settings SET key = :old WHERE key = :new"),
            {"old": old, "new": new},
        )
