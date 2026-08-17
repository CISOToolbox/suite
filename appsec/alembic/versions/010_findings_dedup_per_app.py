"""Make findings.dedup_key unique per application, not globally.

Two apps can legitimately have the same CVE on the same package version
(e.g. both depend on cryptography@46.0.5). The previous global unique
constraint on ``dedup_key`` made trivy_fs upsert blow up on the second
app with ``duplicate key value violates unique constraint
"findings_dedup_key_key"``. The autoflush IntegrityError poisoned the
ORM session, which then prevented the scheduler from marking the job
as ``failed`` — leaving the row stuck in ``running`` and blocking the
app's next scan.

Fix: replace the table-wide unique with a composite unique on
``(application_id, dedup_key)``. The standalone ``ix_findings_dedup_key``
index stays for lookup speed.

Revision ID: 010_findings_dedup_per_app
Revises: 009_schema_alignment
Create Date: 2026-05-12
"""
from alembic import op
from sqlalchemy import inspect

revision = "010_findings_dedup_per_app"
down_revision = "009_schema_alignment"
branch_labels = None
depends_on = None


def _has_constraint(table: str, name: str) -> bool:
    bind = op.get_bind()
    insp = inspect(bind)
    uqs = {u["name"] for u in insp.get_unique_constraints(table)}
    return name in uqs


def _has_index(table: str, name: str) -> bool:
    bind = op.get_bind()
    insp = inspect(bind)
    return name in {i["name"] for i in insp.get_indexes(table)}


def upgrade() -> None:
    # Drop the legacy global-unique constraint if still present.
    # SQLAlchemy named it ``findings_dedup_key_key`` (Postgres default
    # naming for column-level unique=True).
    if _has_constraint("findings", "findings_dedup_key_key"):
        op.drop_constraint("findings_dedup_key_key", "findings", type_="unique")
    # Some legacy DBs may have it as an index rather than a constraint.
    if _has_index("findings", "findings_dedup_key_key"):
        op.drop_index("findings_dedup_key_key", table_name="findings")

    # Composite unique: same dedup_key is allowed across different apps.
    if not _has_constraint("findings", "uq_findings_app_dedup"):
        op.create_unique_constraint(
            "uq_findings_app_dedup",
            "findings",
            ["application_id", "dedup_key"],
        )


def downgrade() -> None:
    # Intentional no-op: reverting to a global unique constraint would
    # fail on any DB that has two apps sharing a CVE.
    pass
