"""Allow one Measure to cover multiple Findings.

Bulk triage "À corriger" across N selected findings used to be a simple
status change (no measure created). The user requires creating ONE
corrective measure per bulk selection. After this migration:

  - measures.finding_ids JSONB[] holds every finding covered by the measure
  - measures.finding_id stays as the "primary" link (first finding) for
    backwards compatibility with the existing ORM relationship. It also
    becomes nullable so a measure can exist standalone (not recommended
    in practice, but the schema must allow it).
  - UNIQUE constraint on finding_id is dropped so a finding covered
    through finding_ids doesn't block a future reassignment.

Idempotent DO-block safe on both fresh and existing DBs.
"""
from __future__ import annotations

from alembic import op

revision = "002_measure_finding_ids"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'measures' AND column_name = 'finding_ids'
        ) THEN
            ALTER TABLE measures ADD COLUMN finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
        END IF;
    END $$;
    """)

    # Backfill: each existing measure covers exactly its own finding_id.
    op.execute("""
    UPDATE measures
       SET finding_ids = jsonb_build_array(finding_id::text)
     WHERE finding_id IS NOT NULL
       AND finding_ids = '[]'::jsonb;
    """)

    # Drop the UNIQUE constraint on finding_id so the 1:1 reverse
    # relationship doesn't prevent reassigning / grouping.
    op.execute("""
    DO $$
    DECLARE cname text;
    BEGIN
        SELECT conname INTO cname
          FROM pg_constraint
         WHERE conrelid = 'measures'::regclass
           AND contype = 'u'
           AND pg_get_constraintdef(oid) LIKE '%(finding_id)%';
        IF cname IS NOT NULL THEN
            EXECUTE 'ALTER TABLE measures DROP CONSTRAINT ' || quote_ident(cname);
        END IF;
    END $$;
    """)


def downgrade() -> None:
    # No-op: keeping the column and relaxed constraint is safe for a
    # rollback. A strict rollback would require merging duplicate
    # coverage back into 1:1 measures which is lossy by design.
    pass
