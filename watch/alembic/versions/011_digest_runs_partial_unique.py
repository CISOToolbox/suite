"""digest_runs: partial unique index (terminal statuses only).

Revision ID: 011_digest_runs_partial_unique
Revises: 010_threat_split
Create Date: 2026-05-14

Background
----------
The original unique constraint ``uq_digest_user_scope_kind_date``
covered every status — including ``skipped_empty``. That made a
specific corner case painful: when a scope was freshly configured
and its threat_matcher hadn't populated rows yet, the next scheduler
tick would stamp ``skipped_empty`` and block any real send for the
rest of the day, even after matches arrived seconds later.

Proposal 2 from the 2026-05-14 redesign keeps ``skipped_empty`` as
informational telemetry but stops it from participating in
idempotence. Only ``sent`` and ``failed`` are terminal.

Schema change
-------------
* Drop the old full-column unique constraint.
* Replace it with a partial unique index whose predicate is
  ``status IN ('sent', 'failed')``.

Application code (`_already_sent_today`, `_stamp_skipped_empty`) is
updated in the same commit to honour the new semantics. The DB
constraint is the safety net in case a future code path forgets.
"""
from alembic import op


revision = "011_digest_runs_partial_unique"
down_revision = "010_threat_split"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_digest_user_scope_kind_date",
        "digest_runs",
        type_="unique",
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_digest_user_scope_kind_date_sent "
        "ON digest_runs (user_email, scope_id, kind, calendar_date) "
        "WHERE status IN ('sent', 'failed')"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_digest_user_scope_kind_date_sent")
    # Recreating the full unique constraint after partial-unique data
    # has been allowed in is risky: there may now be multiple
    # skipped_empty rows for the same (user, scope, kind, day). Collapse
    # them to one before re-adding the constraint.
    op.execute(
        "DELETE FROM digest_runs a "
        "USING digest_runs b "
        "WHERE a.id < b.id "
        "  AND a.user_email = b.user_email "
        "  AND a.scope_id = b.scope_id "
        "  AND a.kind = b.kind "
        "  AND a.calendar_date = b.calendar_date "
        "  AND a.status = 'skipped_empty' "
        "  AND b.status = 'skipped_empty'"
    )
    op.create_unique_constraint(
        "uq_digest_user_scope_kind_date",
        "digest_runs",
        ["user_email", "scope_id", "kind", "calendar_date"],
    )
