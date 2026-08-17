from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ── Auth & Settings ────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(String(500), nullable=True)
    provider = Column(String(50), nullable=False)
    provider_id = Column(String(255), nullable=False)
    role = Column(String(50), default="user", server_default=text("'user'"))
    ai_enabled = Column(String(5), default="false", server_default=text("'false'"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    last_login = Column(DateTime(timezone=True), nullable=True)


class AppSettings(Base):
    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False, default="")


# ── Project ────────────────────────────────────────────────────

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    name = Column(String(255), nullable=False, default="")
    organization = Column(String(255), nullable=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    shared_with = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    # FEAT-33 — bumped ONLY by server-initiated writers (Pilot write-back,
    # restore, schedulers). Guards the blob PUT against stale-tab overwrite.
    server_rev = Column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    metadata_rel = relationship("ProjectMetadata", back_populates="project", uselist=False, cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan", order_by="Asset.sort_order")
    asset_groups = relationship("AssetGroup", back_populates="project", cascade="all, delete-orphan", order_by="AssetGroup.sort_order")
    measures = relationship("Measure", back_populates="project", cascade="all, delete-orphan", order_by="Measure.sort_order")


# ── Project Metadata ───────────────────────────────────────────

class ProjectMetadata(Base):
    __tablename__ = "project_metadata"

    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    organization = Column(String(255), nullable=True)
    created_date = Column(String(20), nullable=True)
    # User-defined asset types on top of the 8 built-ins. Shape:
    # [{id, label, label_en, color}, ...]. Asset.type is a plain
    # VARCHAR so any string value works — this list drives the UI
    # dropdowns, colors and labels.
    custom_asset_types = Column(JSONB, nullable=False, default=list,
                                server_default=text("'[]'::jsonb"))

    project = relationship("Project", back_populates="metadata_rel")


# ── Asset ──────────────────────────────────────────────────────

class Asset(Base):
    __tablename__ = "assets"

    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    nom = Column(String(255), nullable=False, default="")
    type = Column(String(50), nullable=False, default="application")
    description = Column(Text, nullable=True, default="")
    criticite = Column(Integer, nullable=False, default=2)
    proprietaire = Column(String(255), nullable=True, default="")
    localisation = Column(String(255), nullable=True, default="")
    quantite = Column(Integer, nullable=False, default=1)
    os = Column(String(255), nullable=True, default="")
    version = Column(String(100), nullable=True, default="")
    fournisseur = Column(String(255), nullable=True, default="")
    fin_support = Column(String(20), nullable=True, default="")
    fin_vie = Column(String(20), nullable=True, default="")
    statut = Column(String(50), nullable=False, default="actif")
    notes = Column(Text, nullable=True, default="")
    ip_address = Column(String(64), nullable=True, default="")

    # Last login / activity timestamp — populated by CSV imports that
    # carry AD lastLogonTimestamp or equivalent. None when unknown.
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Per-field provenance for cross-connector deduplication.
    #   sources = {
    #     "keys":   {plugin_id: external_key},   # all connector-side keys
    #     "fields": {field_name: plugin_id},     # which plugin last wrote
    #   }
    # See routes/plugins.py::sync_plugin — writes obey the priority
    # column on AssetPluginConfig (higher wins).
    sources = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))

    # Dependencies stored as JSONB array of IDs (assets or groups)
    depends_on = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))

    # License / support contract cycle. Manual renewal date + alert lead.
    #   licence = {date_renouvellement, preavis_jours, cout, devise,
    #              reference, contact}
    # Drives the "Échéances" view and the renewal email alert.
    licence = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="assets")

    __table_args__ = (
        Index("ix_assets_project_type", "project_id", "type"),
        Index("ix_assets_project_statut", "project_id", "statut"),
    )


# ── Asset Group ────────────────────────────────────────────────

class AssetGroup(Base):
    __tablename__ = "asset_groups"

    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    nom = Column(String(255), nullable=False, default="")
    principe = Column(Text, nullable=True, default="")
    criticite = Column(Integer, nullable=False, default=2)
    notes = Column(Text, nullable=True, default="")

    # Complex nested objects as JSONB
    raci = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    politique_sauvegarde = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    politique_supervision = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    politique_maj = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))

    # Member asset IDs stored as JSONB array
    asset_ids = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    # Dependencies on other groups/assets
    depends_on_groups = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="asset_groups")

    __table_args__ = (
        Index("ix_asset_groups_project", "project_id"),
    )


# ── Plugin configs (external asset sources) ──────────────────────
# Connectors pull assets from AD, Intune, EDR, vSphere, etc. Config
# payload (with credentials) is AES-GCM encrypted at rest via crypto.py.
class AssetPluginConfig(Base):
    __tablename__ = "asset_plugin_configs"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    plugin_type = Column(String(50), nullable=False)
    label = Column(String(255), nullable=True, default="")
    enabled = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    # Higher wins when two connectors try to write the same field on the
    # same asset — see routes/plugins.py::sync_plugin.
    priority = Column(Integer, nullable=False, default=100, server_default=text("100"))
    config_enc = Column(Text, nullable=True, default="")
    # Free-form filters the plugin may use (e.g. LDAP base-DN overrides,
    # device groups, tag selectors). JSON dict.
    filters = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    schedule = Column(String(50), nullable=False, default="manual")
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_sync_status = Column(String(50), nullable=True, default="")

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    __table_args__ = (
        Index("ix_asset_plugin_configs_project", "project_id"),
    )


# ── Sync job audit trail ─────────────────────────────────────────
class AssetSyncJob(Base):
    __tablename__ = "asset_sync_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    plugin_id = Column(String(20), nullable=False)
    status = Column(String(50), nullable=False, default="running")
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    # Counters — all optional so different plugins can fill what applies
    assets_found = Column(Integer, nullable=False, default=0)
    assets_created = Column(Integer, nullable=False, default=0)
    assets_updated = Column(Integer, nullable=False, default=0)
    assets_unchanged = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True, default="")

    __table_args__ = (
        Index("ix_asset_sync_jobs_project_plugin", "project_id", "plugin_id"),
        Index("ix_asset_sync_jobs_started", "started_at"),
    )


# ── Measures (FEAT-22) ─────────────────────────────────────────
# Remediation action plan for Asset, mirroring the other modules so the
# items flow into Pilot's consolidated action plan. Two Asset-specific
# columns support auto-generation from echeances:
#   origine  — "manual" | "echeance"
#   asset_id — soft reference (String, NOT a FK) to the asset whose
#              echeance raised the measure. Deliberately not a FK: assets
#              are delete-all + re-inserted on every blob autosave
#              (projects.py::_decompose_data), so a cascade/SET-NULL FK
#              would wipe or null these measures on each save.
#   auto_key — dedup signature "<asset_id>:<kind>:<date>"; NULL for manual
#              measures. The unique index (project_id, auto_key) makes the
#              daily scheduler idempotent (NULLs are distinct in Postgres,
#              so manual measures never collide).
# Measures live OUTSIDE the blob decompose (see projects.py): a dedicated
# REST CRUD owns them; _reconstruct_data exposes them read-only for export.

class Measure(Base):
    __tablename__ = "measures"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    title = Column(String(500), nullable=False, default="")
    description = Column(Text, nullable=True, default="")
    statut = Column(String(50), nullable=False, default="a_faire")
    responsable = Column(String(255), nullable=True, default="")
    echeance = Column(String(20), nullable=True, default="")

    progress_log = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))

    origine = Column(String(20), nullable=False, default="manual", server_default=text("'manual'"))
    asset_id = Column(String(20), nullable=True, default="")
    auto_key = Column(String(160), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="measures")

    __table_args__ = (
        Index("ix_asset_measures_project_statut", "project_id", "statut"),
        Index("uq_asset_measures_auto_key", "project_id", "auto_key", unique=True),
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
