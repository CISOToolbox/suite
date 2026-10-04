"""The SAST scanner is called "sast" (Opengrep replaces Semgrep) (FEAT-52)

Revision ID: 016_sast_scanner
Revises: 015_nonconformity_project
Create Date: 2026-10-03

The stored scanner id follows the engine change: applications' enabled
scanners, findings, scan jobs and ignore-rule criteria move from "semgrep" to
"sast". Finding keys are not rewritten here: the first Opengrep scan carries
each Semgrep-era finding over to its new key (src/findings_dedup.py), and
marks the ones it cannot in the new migration_closed_at column, their former
status kept in migration_prev_status.
"""
from alembic import op
import sqlalchemy as sa

revision = "016_sast_scanner"
down_revision = "015_nonconformity_project"
branch_labels = None
depends_on = None


def _rename(old: str, new: str) -> None:
    op.execute(f"""
        UPDATE applications SET enabled_scanners = (
            SELECT jsonb_agg(CASE WHEN x = '{old}' THEN '{new}' ELSE x END ORDER BY n)
            FROM jsonb_array_elements_text(enabled_scanners) WITH ORDINALITY AS t(x, n))
        WHERE enabled_scanners ? '{old}'
    """)
    op.execute(f"UPDATE findings SET scanner = '{new}' WHERE scanner = '{old}'")
    op.execute(f"UPDATE scan_jobs SET scanner = '{new}' WHERE scanner = '{old}'")
    # scanner_rule criteria read "<scanner>", "<scanner>:<rule id>" or a glob
    # starting with the scanner ("semgrep*").
    op.execute(f"""
        UPDATE ignore_rules SET criteria = (
            SELECT jsonb_agg(CASE
                WHEN e->>'type' = 'scanner_rule'
                     AND e->>'value' LIKE '{old}%'
                THEN jsonb_set(e, '{{value}}', to_jsonb('{new}' || substr(e->>'value', {len(old) + 1})))
                ELSE e END ORDER BY n)
            FROM jsonb_array_elements(criteria) WITH ORDINALITY AS t(e, n))
        WHERE criteria::text LIKE '%{old}%'
    """)


def upgrade() -> None:
    op.add_column("findings", sa.Column("migration_closed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("migration_prev_status", sa.String(30), nullable=True))
    _rename("semgrep", "sast")


def downgrade() -> None:
    _rename("sast", "semgrep")
    op.drop_column("findings", "migration_prev_status")
    op.drop_column("findings", "migration_closed_at")
