from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, String, Text, text,
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
    owner_id = Column(UUID(as_uuid=True),
                      # SET NULL, not the NO ACTION default: deleting a user must
                      # not be blocked by the objects they happen to own. The
                      # ownership idiom already tolerates a null owner.
                      ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    shared_with = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    # FEAT-33 — bumped ONLY by server-initiated writers (Pilot write-back,
    # restore, schedulers). Guards the blob PUT against stale-tab overwrite.
    server_rev = Column(Integer, nullable=False, default=0, server_default=text("0"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    metadata_rel = relationship("ProjectMetadata", back_populates="project", uselist=False, cascade="all, delete-orphan")
    si_users = relationship("SiUser", back_populates="project", cascade="all, delete-orphan", order_by="SiUser.sort_order")
    applications = relationship("Application", back_populates="project", cascade="all, delete-orphan", order_by="Application.sort_order")
    reviews = relationship("Review", back_populates="project", cascade="all, delete-orphan", order_by="Review.sort_order")
    measures = relationship("Measure", back_populates="project", cascade="all, delete-orphan", order_by="Measure.sort_order")
    service_accounts = relationship("ServiceAccount", back_populates="project", cascade="all, delete-orphan", order_by="ServiceAccount.sort_order")
    plugin_configs = relationship("PluginConfig", back_populates="project", cascade="all, delete-orphan", order_by="PluginConfig.sort_order")


class ProjectMetadata(Base):
    __tablename__ = "project_metadata"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    organization = Column(String(255), nullable=True)
    created_date = Column(String(20), nullable=True)
    project = relationship("Project", back_populates="metadata_rel")


# ── SI Users ───────────────────────────────────────────────────

class SiUser(Base):
    __tablename__ = "si_users"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    nom = Column(String(255), nullable=False, default="")
    prenom = Column(String(255), nullable=False, default="")
    email = Column(String(255), nullable=False, default="")
    # statut ∈ {'actif', 'ancien', 'recrutement'} — CHECK-constrained
    # in migration 008. Pilot's 'actif/inactif' maps via _STATUT_MAP.
    statut = Column(String(50), nullable=False, default="actif")
    # type_compte ∈ {'salarie','prestataire','stagiaire','alternant'}
    # (CHECK-constrained). Drives whether NDA proof is required.
    type_compte = Column(String(50), nullable=False, default="salarie")
    fonction = Column(String(255), nullable=True, default="")

    # Team/department (free text, all user types).
    equipe = Column(String(255), nullable=False, default="", server_default="")
    # Planned contract end date (ISO string). Required for every type
    # except 'salarie' — enforced at the HTTP layer, see routes/si_users.py.
    date_fin_contrat = Column(String(20), nullable=False, default="", server_default="")
    # Hierarchy: email of the user's manager. Used to authorize who may edit
    # this user's requested entitlements (manager chain), see FEAT-15.
    manager_email = Column(String(255), nullable=False, default="", server_default="")

    # Compliance proofs — uniform shape: boolean + date + justification.
    politique_validee = Column(Boolean, nullable=False, default=False)
    politique_date = Column(String(20), nullable=True, default="")
    politique_justification = Column(Text, nullable=False, default="")
    mfa_active = Column(Boolean, nullable=False, default=False)
    mfa_date = Column(String(20), nullable=True, default="")
    mfa_justification = Column(Text, nullable=False, default="")
    sensibilisation = Column(Boolean, nullable=False, default=False)
    sensibilisation_date = Column(String(20), nullable=True, default="")
    sensibilisation_justification = Column(Text, nullable=False, default="")
    # Cumulative per-training awareness history fed by the Proofpoint PSAT
    # connector (never pruned). Keyed by campaign name:
    #   { campaign: {completed, due_date, completion_date, statut,
    #                first_seen, last_seen} }
    # The `sensibilisation` bool above is a DERIVED compliance state computed
    # from the latest sync snapshot (see routes/internal.py awareness_sync).
    sensibilisation_history = Column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    background_check = Column(Boolean, nullable=False, default=False)
    background_check_date = Column(String(20), nullable=False, default="")
    background_check_justification = Column(Text, nullable=False, default="")
    # Legacy URL field — kept for backwards compatibility with existing
    # rows. New UI writes to background_check_justification instead.
    background_check_url = Column(String(500), nullable=True, default="")
    # NDA (mandatory for prestataires, optional for other user types).
    nda_signed = Column(Boolean, nullable=False, default=False)
    nda_date = Column(String(20), nullable=False, default="")
    nda_justification = Column(Text, nullable=False, default="")

    # Populated by connector sync (LDAP/AD lastLogonTimestamp,
    # Entra signInActivity.lastSignInDateTime, etc.). None when the
    # connector didn't provide it or the user was entered manually.
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    # IdP account active/enabled state from connector sync (Entra
    # accountEnabled, Okta status, etc.). NULL = unknown / manual entry.
    account_enabled = Column(Boolean, nullable=True)

    # Source of the canonical identity fields (nom / prenom / email /
    # fonction). Values: "" (manual entry), "pilot" (managed by the
    # central directory — fields are read-only from the UI), "connector"
    # (populated by a review import but free to edit).
    sync_source = Column(String(20), nullable=False, default="", server_default="")

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="si_users")

    __table_args__ = (
        Index("ix_si_users_project_email", "project_id", "email"),
        Index("ix_si_users_project_statut", "project_id", "statut"),
    )


# ── Applications ───────────────────────────────────────────────

class Application(Base):
    __tablename__ = "applications"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    nom = Column(String(255), nullable=False, default="")
    url = Column(String(500), nullable=True, default="")
    reviewers = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    frequence_revue = Column(String(50), nullable=False, default="semestrielle")
    # Perimeter typing (FEAT-15 Lot 2). UI labels "applications" as
    # "périmètres". type ∈ {application, infrastructure, physique}.
    type = Column(String(20), nullable=False, default="application", server_default="application")
    # Free-text role names defined for this perimeter (used by the
    # requested-entitlements picker in Lot 4).
    roles = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="applications")

    __table_args__ = (
        Index("ix_applications_project", "project_id"),
    )


# ── Reviews ────────────────────────────────────────────────────

class Review(Base):
    __tablename__ = "reviews"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    application_id = Column(String(20), nullable=False)
    status = Column(String(50), nullable=False, default="en_cours")
    started_at = Column(String(20), nullable=True, default="")
    closed_at = Column(String(20), nullable=True, default="")
    closed_by = Column(String(255), nullable=True, default="")

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="reviews")
    entries = relationship("ReviewEntry", back_populates="review", cascade="all, delete-orphan", order_by="ReviewEntry.sort_order")

    __table_args__ = (
        Index("ix_reviews_project_status", "project_id", "status"),
    )


# ── Review Entries ─────────────────────────────────────────────

class ReviewEntry(Base):
    __tablename__ = "review_entries"
    project_id = Column(UUID(as_uuid=True), primary_key=True)
    review_id = Column(String(20), primary_key=True)
    id = Column(String(30), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    type_compte = Column(String(50), nullable=False, default="personnel")
    email_or_login = Column(String(255), nullable=False, default="")
    # Identity copied from the connector at import time — shown in the
    # review table and used as a fallback for SI matching when the email
    # doesn't resolve. Empty when the source has no name.
    nom = Column(String(255), nullable=False, default="", server_default="")
    prenom = Column(String(255), nullable=False, default="", server_default="")
    roles = Column(Text, nullable=True, default="")
    groups = Column(Text, nullable=True, default="")
    si_user_id = Column(String(20), nullable=True)

    decision = Column(String(50), nullable=False, default="pending")
    decided_by = Column(String(255), nullable=True, default="")
    decided_at = Column(String(20), nullable=True, default="")
    notes = Column(Text, nullable=True, default="")

    # Copied from the connector at import time — shown in the review
    # table for every entry (matched or orphan) without depending on
    # a matched SiUser being present.
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    # IdP account active/enabled state, copied from the connector at import
    # time (same rationale as last_login_at). NULL = unknown.
    account_enabled = Column(Boolean, nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    review = relationship("Review", back_populates="entries")

    __table_args__ = (
        ForeignKeyConstraint(
            ["project_id", "review_id"],
            ["reviews.project_id", "reviews.id"],
            ondelete="CASCADE",
        ),
        Index("ix_review_entries_review", "project_id", "review_id"),
    )


# ── Measures ───────────────────────────────────────────────────

class Measure(Base):
    __tablename__ = "measures"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    review_entry_id = Column(String(30), nullable=True, default="")
    title = Column(String(500), nullable=False, default="")
    description = Column(Text, nullable=True, default="")
    statut = Column(String(50), nullable=False, default="a_faire")
    responsable = Column(String(255), nullable=True, default="")
    echeance = Column(String(20), nullable=True, default="")

    progress_log = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="measures")

    __table_args__ = (
        Index("ix_measures_project_statut", "project_id", "statut"),
    )


# ── Service Accounts ─────────────────────────────────────────

class ServiceAccount(Base):
    __tablename__ = "service_accounts"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    name = Column(String(255), nullable=False, default="")
    identifier = Column(String(255), nullable=True, default="")
    platform = Column(String(100), nullable=True, default="")
    application_id = Column(String(20), nullable=True, default="")
    purpose = Column(Text, nullable=True, default="")
    secret_storage = Column(String(50), nullable=True, default="unknown")
    rotation_policy = Column(String(50), nullable=True, default="unknown")
    last_rotation = Column(String(20), nullable=True, default="")
    owners = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    risk_level = Column(String(20), nullable=True, default="medium")
    notes = Column(Text, nullable=True, default="")

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="service_accounts")

    __table_args__ = (
        Index("ix_service_accounts_project", "project_id"),
    )


# ── Plugin Configs ────────────────────────────────────────────

class PluginConfig(Base):
    __tablename__ = "plugin_configs"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)
    sort_order = Column(Integer, nullable=False, default=0)

    plugin_type = Column(String(50), nullable=False)
    label = Column(String(255), nullable=True, default="")
    enabled = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    config_enc = Column(Text, nullable=True, default="")
    group_filters = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    application_id = Column(String(20), nullable=True, default="")
    schedule = Column(String(50), nullable=False, default="manual")
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_sync_status = Column(String(50), nullable=True, default="")

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    project = relationship("Project", back_populates="plugin_configs")

    __table_args__ = (
        Index("ix_plugin_configs_project", "project_id"),
    )


# ── Sync Jobs ─────────────────────────────────────────────────

class SyncJob(Base):
    __tablename__ = "sync_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    plugin_id = Column(String(20), nullable=False)
    status = Column(String(50), nullable=False, default="running")
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    users_found = Column(Integer, nullable=False, default=0)
    users_created = Column(Integer, nullable=False, default=0)
    users_updated = Column(Integer, nullable=False, default=0)
    entries_created = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True, default="")

    __table_args__ = (
        Index("ix_sync_jobs_project_plugin", "project_id", "plugin_id"),
    )


# ── Sync Snapshots ────────────────────────────────────────────

class SyncSnapshot(Base):
    __tablename__ = "sync_snapshots"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    plugin_id = Column(String(20), nullable=False)
    job_id = Column(UUID(as_uuid=True), nullable=True)
    snapshot_data = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))


# ── Requested entitlements + audit (FEAT-15 Lot 4) ─────────────

class RequestedEntitlement(Base):
    """An access right requested for a user on a perimeter+role. The record
    itself is the validation trace (created_by / created_at = who requested it
    and when). Edited only by an admin or someone in the user's manager chain.
    Lives outside the project blob (its audit is server-authored)."""
    __tablename__ = "requested_entitlements"
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    id = Column(String(20), primary_key=True)  # ENT-001
    si_user_id = Column(String(20), nullable=False)
    perimetre_id = Column(String(20), nullable=False)  # references applications.id
    role = Column(Text, nullable=False, default="")
    status = Column(String(30), nullable=False, default="demandee", server_default="demandee")
    created_by = Column(String(255), nullable=False, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_by = Column(String(255), nullable=False, default="")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    __table_args__ = (
        Index("ix_entitlements_project_user", "project_id", "si_user_id"),
    )


class EntitlementAudit(Base):
    """Append-only audit of entitlement changes. Actor + timestamp are always
    server-assigned; rows are never updated or deleted."""
    __tablename__ = "entitlement_audit"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    si_user_id = Column(String(20), nullable=False)
    entitlement_id = Column(String(20), nullable=True)
    action = Column(String(20), nullable=False)  # add | modify | remove
    field = Column(String(50), nullable=False, default="")
    old_value = Column(Text, nullable=False, default="")
    new_value = Column(Text, nullable=False, default="")
    actor = Column(String(255), nullable=False, default="")
    at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    __table_args__ = (
        Index("ix_entitlement_audit_project_user", "project_id", "si_user_id"),
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
