"""collapse to a single canonical project

Revision ID: 009_canonical_project
Revises: 008_user_type_proofs
Create Date: 2026-05-29

Single-project model (docs/CHANTIER_PROJET_UNIQUE.md): the suite holds one
client / one IS = ONE project, with a well-known UUID shared across every
module and Pilot. This migration collapses an existing per-deployment random
project onto that canonical id, non-destructively (data is repointed, not
dropped).

Strategy:
  - 0 projects  → insert the canonical project.
  - 1 project, already canonical → no-op (idempotent).
  - 1 project, other id → insert canonical (copying its fields), repoint every
    child table's project_id, delete the old project row.
  - >1 projects → ABORT loudly: a real multi-project deployment needs a manual
    merge decision. Never silently pick one.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "009_canonical_project"
down_revision = "008_user_type_proofs"
branch_labels = None
depends_on = None

CANONICAL = "00000000-0000-0000-0000-000000000001"

# Every table carrying project_id in Access (project_metadata + entities).
# review_entries / sync_jobs / sync_snapshots included even though some carry
# project_id without an explicit ForeignKey (composite FK).
CHILD_TABLES = [
    "project_metadata",
    "si_users",
    "applications",
    "reviews",
    "review_entries",
    "measures",
    "service_accounts",
    "plugin_configs",
    "sync_jobs",
    "sync_snapshots",
]


def upgrade() -> None:
    conn = op.get_bind()
    ids = [str(r[0]) for r in conn.execute(sa.text("SELECT id FROM projects")).fetchall()]

    if CANONICAL in ids:
        others = [i for i in ids if i != CANONICAL]
        if others:
            raise RuntimeError(
                f"Canonical project coexists with {len(others)} other project(s) "
                f"({others}); manual merge required before this migration."
            )
        return  # already collapsed

    if len(ids) == 0:
        conn.execute(
            sa.text("INSERT INTO projects (id, name) VALUES (:c, 'Projet principal')"),
            {"c": CANONICAL},
        )
        return

    if len(ids) > 1:
        raise RuntimeError(
            f"{len(ids)} projects found ({ids}); the single-project collapse requires "
            "exactly one. Merge them manually, then re-run."
        )

    old = ids[0]
    # Composite FKs (e.g. review_entries(project_id, review_id) → reviews) and
    # the lack of ON UPDATE CASCADE make a sequential per-table repoint violate
    # FKs mid-flight. Disable FK trigger enforcement for THIS transaction only
    # (SET LOCAL auto-reverts at commit/rollback), rename the project id and
    # repoint every child; the final state is fully consistent so no constraint
    # is left dangling. Requires DB superuser (true for the suite's per-module
    # Postgres roles).
    conn.execute(sa.text("SET LOCAL session_replication_role = 'replica'"))
    conn.execute(
        sa.text("UPDATE projects SET id = :c WHERE id = :old"),
        {"c": CANONICAL, "old": old},
    )
    for tbl in CHILD_TABLES:
        conn.execute(
            sa.text(f"UPDATE {tbl} SET project_id = :c WHERE project_id = :old"),
            {"c": CANONICAL, "old": old},
        )


def downgrade() -> None:
    # Irreversible by design: the original random project id is not recoverable
    # once collapsed. No-op downgrade (the canonical project simply remains).
    pass
