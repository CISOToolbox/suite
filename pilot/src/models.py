from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(String(500), nullable=True)
    provider = Column(String(50), nullable=False)
    provider_id = Column(String(255), nullable=False)
    role = Column(String(50), default="user", server_default=text("'user'"))
    modules = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    permissions = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    ai_enabled = Column(String(5), default="false", server_default=text("'false'"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    last_login = Column(DateTime(timezone=True), nullable=True)


class Personnel(Base):
    """Central personnel directory shared across all modules."""
    __tablename__ = "personnel"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    nom = Column(String(255), nullable=False, default="")
    prenom = Column(String(255), nullable=False, default="")
    email = Column(String(255), unique=True, nullable=False)
    fonction = Column(String(255), nullable=True, default="")
    departement = Column(String(255), nullable=True, default="")
    statut = Column(String(50), nullable=False, default="actif")  # actif, inactif, externe
    telephone = Column(String(50), nullable=True, default="")
    site = Column(String(255), nullable=True, default="")
    manager_email = Column(String(255), nullable=True, default="")
    # Provenance: "" = managed in Pilot (editable), "access" = fed from Access
    # (an HR connector lives there). "access" rows are read-only in Pilot and
    # never pushed back to Access (one-directional, no loop).
    sync_source = Column(String(20), nullable=False, default="", server_default=text("''"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))


class AppSettings(Base):
    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False, default="")


class ModuleRegistry(Base):
    __tablename__ = "module_registry"

    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    internal_url = Column(String(500), nullable=False)
    external_url = Column(String(500), nullable=False)
    status = Column(String(20), default="active")
    last_health = Column(DateTime(timezone=True), nullable=True)


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    name = Column(String(500), nullable=False, default="")
    description = Column(String(2000), nullable=True)
    status = Column(String(50), default="planned")
    priority = Column(String(20), default="medium")
    responsible = Column(String(255), nullable=True)
    owner_id = Column(UUID(as_uuid=True), nullable=True)
    start_date = Column(DateTime(timezone=True), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    completed_date = Column(DateTime(timezone=True), nullable=True)
    tags = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))


class ProjectMeasure(Base):
    __tablename__ = "project_measures"

    project_id = Column(UUID(as_uuid=True), primary_key=True)
    measure_id = Column(UUID(as_uuid=True), primary_key=True)


class NotificationPrefs(Base):
    """FEAT-34 — weekly deadline-digest settings, one row per user (opt-in)."""
    __tablename__ = "notification_prefs"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    enabled = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    day_of_week = Column(SmallInteger, nullable=False, default=0, server_default="0")  # 0=lundi … 6=dimanche
    upcoming_days = Column(SmallInteger, nullable=False, default=14, server_default="14")
    include_overdue = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    scope = Column(String(10), nullable=False, default="mine", server_default="mine")  # mine | all (admin)
    modules = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))  # [] = tous
    lang = Column(String(5), nullable=False, default="fr", server_default="fr")
    subject_prefix = Column(String(60), nullable=False, default="[CISO Toolbox]", server_default="[CISO Toolbox]")
    module_prefs = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))  # {"appsec": {...}} — FEAT-35
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))


class DigestRun(Base):
    """FEAT-34 — deadline-digest send journal (Watch pattern). The unique
    (user_id, iso_week) pair makes the weekly send idempotent."""
    __tablename__ = "digest_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    iso_week = Column(String(10), nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    status = Column(String(20), nullable=False)
    items_count = Column(Integer, nullable=False, default=0, server_default="0")
    error_message = Column(Text, nullable=False, default="", server_default="")
    body_html = Column(Text, nullable=False, default="", server_default="")


class MeasureGroup(Base):
    """FEAT-11 — meta-measure: N cache measures steered as one. Canonical
    operational fields live here; title/description stay per-module."""
    __tablename__ = "measure_groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    ref = Column(String(20), nullable=False, default="", server_default="")  # META-NNN, assigned at creation
    title = Column(String(500), nullable=False, default="")
    status = Column(String(30), nullable=False, default="planned")
    due_date = Column(String(20), nullable=True, default="")
    responsible = Column(String(255), nullable=True, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))


class MeasureGroupMember(Base):
    __tablename__ = "measure_group_members"

    group_id = Column(UUID(as_uuid=True), ForeignKey("measure_groups.id", ondelete="CASCADE"), primary_key=True)
    measure_id = Column(UUID(as_uuid=True), ForeignKey("measure_cache.id", ondelete="CASCADE"), primary_key=True)

    __table_args__ = (
        # A measure belongs to AT MOST one group (FEAT-11 invariant).
        UniqueConstraint("measure_id", name="uq_measure_group_member"),
    )


class MeasureCache(Base):
    __tablename__ = "measure_cache"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    module = Column(String(50), nullable=False)
    source_id = Column(String(100), nullable=False)
    entity_id = Column(String(100), nullable=True)
    entity_name = Column(String(255), nullable=True)
    data = Column(JSONB, nullable=False, default=dict)
    synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("module", "source_id", name="uq_measure_cache_module_source"),
        Index("ix_measure_cache_module_source", "module", "source_id"),
        # Expression indexes for the dashboard's JSONB predicates (upcoming
        # deadlines filter/sort by due_date, completed-count filters by status).
        # Without them each dashboard GET seq-scans measure_cache twice.
        Index("ix_measure_cache_due_date", data["due_date"].astext),
        Index("ix_measure_cache_status", data["status"].astext),
    )


# FEAT-08: consolidated evidence/proof registry — twin of MeasureCache, fed by
# each module's GET /api/internal/evidences (pull) + /api/evidences/notify (push).
class EvidenceCache(Base):
    __tablename__ = "evidence_cache"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    module = Column(String(50), nullable=False)
    source_id = Column(String(100), nullable=False)
    entity_id = Column(String(100), nullable=True)
    entity_name = Column(String(255), nullable=True)
    status = Column(String(20), nullable=True)   # valide|bientot|expiree|na (recomputed by the source)
    data = Column(JSONB, nullable=False, default=dict)
    synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("module", "source_id", name="uq_evidence_cache_module_source"),
        Index("ix_evidence_cache_module_source", "module", "source_id"),
    )


# ---------------------------------------------------------------------------
# KPI feature (phase 1) — catalogue of indicators, multi-framework mapping,
# append-only time-series of values. ``formula`` and ``connector_config`` are
# nullable phase-2 hooks (formula editor, native integrations) so future
# changes don't require a breaking migration.
# ---------------------------------------------------------------------------


class KpiDefinition(Base):
    """A KPI definition. ``source_type='auto'`` is computed by Pilot from
    a module's stats; ``source_type='external'`` is fed via the universal
    ingest endpoint (manual UI or plugin)."""

    __tablename__ = "kpi_definition"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    code = Column(String(64), unique=True, nullable=False)
    name_fr = Column(String(200), nullable=False)
    name_en = Column(String(200), nullable=False)
    description_fr = Column(Text, nullable=True)
    description_en = Column(Text, nullable=True)
    # 'govern' | 'identify' | 'protect' | 'detect' | 'respond' | 'recover'
    category_primary = Column(String(40), nullable=False)
    # '%' | 'count' | 'days' | 'score' | 'currency' | 'ratio'
    unit = Column(String(20), nullable=False)
    # 'higher_better' | 'lower_better'
    direction = Column(String(20), nullable=False)
    # 'auto' | 'external'  (phase-2 will add 'computed' | 'integration')
    source_type = Column(String(20), nullable=False)
    source_module = Column(String(40), nullable=True)
    source_metric = Column(String(200), nullable=True)
    # Phase-2 hooks (kept nullable to avoid a breaking migration).
    formula = Column(Text, nullable=True)
    connector_config = Column(JSONB, nullable=True)
    target = Column(Numeric(15, 4), nullable=True)
    threshold_amber = Column(Numeric(15, 4), nullable=True)
    threshold_red = Column(Numeric(15, 4), nullable=True)
    active = Column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("NOW()"),
    )
    updated_at = Column(
        DateTime(timezone=True),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=True,
    )
    # Wall-clock of the last SUCCESSFUL value sync (auto scheduler or a manual
    # connector run). Set in routes.kpis._ingest, which is only reached on
    # success — a failed fetch never ingests, so this is never bumped on error.
    last_synced_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_kpi_definition_code", "code"),
        Index("ix_kpi_definition_category", "category_primary"),
    )


class KpiTombstone(Base):
    """Codes of KPI definitions an admin deliberately deleted. The catalogue
    seed (``seed_kpi_catalog``) re-inserts any catalogue entry missing from the
    DB on every restart, which would resurrect a deleted built-in KPI. The seed
    skips codes listed here so a deletion persists across restarts/redeploys."""

    __tablename__ = "kpi_tombstone"

    code = Column(String(64), primary_key=True)
    deleted_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("NOW()"),
    )


class KpiFrameworkMapping(Base):
    """Many-to-many between a KPI and reference framework controls.

    A single KPI can map to controls of several frameworks at once
    (NIST CSF 2.0 + ISO 27001:2022 + CIS v8…). The UI uses this to
    re-organize the dashboard grid by the selected framework."""

    __tablename__ = "kpi_framework_mapping"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    kpi_id = Column(
        UUID(as_uuid=True),
        ForeignKey("kpi_definition.id", ondelete="CASCADE"),
        nullable=False,
    )
    # 'NIST_CSF_2' | 'ISO_27001_2022' | 'CIS_v8' | 'DORA' | 'NIS2'
    framework_code = Column(String(40), nullable=False)
    ref_code = Column(String(80), nullable=False)
    ref_label_fr = Column(String(300), nullable=True)
    ref_label_en = Column(String(300), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "kpi_id",
            "framework_code",
            "ref_code",
            name="uq_kpi_framework_mapping",
        ),
        Index("ix_kpi_framework_mapping_kpi", "kpi_id"),
        Index(
            "ix_kpi_framework_mapping_framework", "framework_code", "ref_code"
        ),
    )


class KpiSnapshot(Base):
    """Append-only time-series of KPI values.

    Idempotent on ``(kpi_id, captured_at, source)``: replaying the same
    datapoint from a plugin retry is a no-op, which makes the ingest
    endpoint safe to retry without a dedup lookup.

    ``raw_payload`` archives the original ingestion body so a plugin's
    extra context (asset count, scope, etc.) can be audited later
    without growing the schema."""

    __tablename__ = "kpi_snapshot"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    kpi_id = Column(
        UUID(as_uuid=True),
        ForeignKey("kpi_definition.id", ondelete="CASCADE"),
        nullable=False,
    )
    value = Column(Numeric(15, 4), nullable=False)
    captured_at = Column(DateTime(timezone=True), nullable=False)
    # 'auto' | 'manual:<email>' | 'plugin:<name>'
    source = Column(String(80), nullable=False)
    raw_payload = Column(JSONB, nullable=True)
    note = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "kpi_id", "captured_at", "source", name="uq_kpi_snapshot_idem"
        ),
        Index("ix_kpi_snapshot_kpi_captured", "kpi_id", "captured_at"),
    )



# ── Append-only server-side write journal (FEAT-30 P1.6) ──────────────
# Created by Base.metadata.create_all at startup (no migration needed for
# a new table). Written via src.audit.log_write — see audit_common master.
class AuditLog(Base):
    """Append-only: never UPDATEd/DELETEd (retention purge excepted).
    entity_type/entity_id tie a line to the exact restorable object."""
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    logged_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"), index=True)
    user_email = Column(String(255), nullable=False, default="")
    user_name = Column(String(255), nullable=False, default="")
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(500), nullable=False, default="")
    entity_type = Column(String(50), nullable=False, default="")
    entity_id = Column(String(64), nullable=False, default="", index=True)
    details = Column(Text, nullable=False, default="")
    ip_address = Column(String(64), nullable=False, default="")
