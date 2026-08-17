"""KPI tables — definitions, framework mappings, snapshots.

Phase 1 of the Pilot KPI feature. Three tables:

* ``kpi_definition``        — catalogue of indicators. Seeded with ~12 built-ins
                              + room for user-defined ones. Holds the target,
                              amber/red thresholds and (for auto KPIs) the path
                              into a module's ``/api/internal/stats`` payload.
                              ``formula`` and ``connector_config`` are
                              phase-2 hooks (DSL editor + native integrations).
* ``kpi_framework_mapping`` — many-to-many between a KPI and reference
                              frameworks (NIST CSF 2.0, ISO 27001:2022,
                              CIS v8, DORA, NIS2…). A KPI may map to several
                              controls of several frameworks at once.
* ``kpi_snapshot``          — append-only time series. Idempotent on
                              ``(kpi_id, captured_at, source)``: re-ingesting
                              the same datapoint is a no-op, which makes the
                              ingest API safe to retry from plugins.

Revision ID: 002_kpi
Revises: 001_baseline
Create Date: 2026-05-18
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "002_kpi"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kpi_definition",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name_fr", sa.String(200), nullable=False),
        sa.Column("name_en", sa.String(200), nullable=False),
        sa.Column("description_fr", sa.Text, nullable=True),
        sa.Column("description_en", sa.Text, nullable=True),
        # 'govern' | 'identify' | 'protect' | 'detect' | 'respond' | 'recover'
        sa.Column("category_primary", sa.String(40), nullable=False),
        # '%' | 'count' | 'days' | 'score' | 'currency' | 'ratio'
        sa.Column("unit", sa.String(20), nullable=False),
        # 'higher_better' | 'lower_better'
        sa.Column("direction", sa.String(20), nullable=False),
        # 'auto' | 'external' (phase-2: 'computed' | 'integration')
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("source_module", sa.String(40), nullable=True),
        # JSONPath-style hint into a module's stats payload, e.g. ``$.posture.score``
        sa.Column("source_metric", sa.String(200), nullable=True),
        # Phase-2 hooks. Reserved nullable columns to avoid a breaking
        # migration when the formula editor / native integrations land.
        sa.Column("formula", sa.Text, nullable=True),
        sa.Column(
            "connector_config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("target", sa.Numeric(15, 4), nullable=True),
        sa.Column("threshold_amber", sa.Numeric(15, 4), nullable=True),
        sa.Column("threshold_red", sa.Numeric(15, 4), nullable=True),
        sa.Column(
            "active",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_kpi_definition_code", "kpi_definition", ["code"])
    op.create_index(
        "ix_kpi_definition_category", "kpi_definition", ["category_primary"]
    )

    op.create_table(
        "kpi_framework_mapping",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "kpi_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("kpi_definition.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # 'NIST_CSF_2' | 'ISO_27001_2022' | 'CIS_v8' | 'DORA' | 'NIS2'
        sa.Column("framework_code", sa.String(40), nullable=False),
        sa.Column("ref_code", sa.String(80), nullable=False),
        sa.Column("ref_label_fr", sa.String(300), nullable=True),
        sa.Column("ref_label_en", sa.String(300), nullable=True),
        sa.UniqueConstraint(
            "kpi_id",
            "framework_code",
            "ref_code",
            name="uq_kpi_framework_mapping",
        ),
    )
    op.create_index(
        "ix_kpi_framework_mapping_kpi", "kpi_framework_mapping", ["kpi_id"]
    )
    op.create_index(
        "ix_kpi_framework_mapping_framework",
        "kpi_framework_mapping",
        ["framework_code", "ref_code"],
    )

    op.create_table(
        "kpi_snapshot",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "kpi_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("kpi_definition.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Numeric(15, 4), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        # 'auto' | 'manual:<email>' | 'plugin:<name>'
        sa.Column("source", sa.String(80), nullable=False),
        sa.Column(
            "raw_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("note", sa.Text, nullable=True),
        sa.UniqueConstraint(
            "kpi_id",
            "captured_at",
            "source",
            name="uq_kpi_snapshot_idem",
        ),
    )
    op.create_index(
        "ix_kpi_snapshot_kpi_captured",
        "kpi_snapshot",
        ["kpi_id", "captured_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_kpi_snapshot_kpi_captured", table_name="kpi_snapshot")
    op.drop_table("kpi_snapshot")
    op.drop_index(
        "ix_kpi_framework_mapping_framework", table_name="kpi_framework_mapping"
    )
    op.drop_index(
        "ix_kpi_framework_mapping_kpi", table_name="kpi_framework_mapping"
    )
    op.drop_table("kpi_framework_mapping")
    op.drop_index("ix_kpi_definition_category", table_name="kpi_definition")
    op.drop_index("ix_kpi_definition_code", table_name="kpi_definition")
    op.drop_table("kpi_definition")
