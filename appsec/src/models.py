from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text, Index,
    ForeignKey, UniqueConstraint, text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(320), unique=True, nullable=False)
    name = Column(String(255), default="")
    picture = Column(String(500), default="")
    provider = Column(String(50), default="")
    provider_id = Column(String(255), default="")
    role = Column(String(20), default="user", server_default=text("'user'"))
    ai_enabled = Column(String(5), default="false", server_default=text("'false'"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)


class AppSettings(Base):
    __tablename__ = "app_settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text, default="")


class Application(Base):
    __tablename__ = "applications"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    repo_url = Column(String(500), default="")
    repo_branch = Column(String(100), default="main")
    repo_token_encrypted = Column(Text, default="")
    # Monorepo support: list of subdirectories to scan within the cloned
    # repo. Empty list = scan the entire repo (default). Example:
    # ["backend-clients/demo-docker/risk", "shared"]
    scan_paths = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    docker_images = Column(JSONB, default=list)
    image_token_encrypted = Column(Text, default="")
    scan_frequency_hours = Column(Integer, default=24)
    enabled_scanners = Column(JSONB, default=lambda: ["trivy_fs", "gitleaks", "semgrep", "trivy_image"])
    enabled = Column(Boolean, default=True, server_default=text("true"))
    criticality = Column(String(20), default="medium")
    owner_id = Column(UUID(as_uuid=True), nullable=True)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    last_scan_commit = Column(String(64), default="")
    # FEAT-35 — WHO gets notified about this app ([] = silence) + email
    # language for recipients without a suite account.
    notification_emails = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    notification_lang = Column(String(5), nullable=False, default="en", server_default="en")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    findings = relationship("Finding", back_populates="application", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="application", cascade="all, delete-orphan")
    sbom_entries = relationship("SBOMEntry", back_populates="application", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id = Column(UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    scanner = Column(String(50), nullable=False)
    status = Column(String(20), default="pending", server_default=text("'pending'"))
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    findings_count = Column(Integer, default=0)
    diff = Column(JSONB, default=dict)
    error = Column(Text, default="")
    triggered_by = Column(String(255), default="manual")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    application = relationship("Application", back_populates="scan_jobs")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id = Column(UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    scanner = Column(String(100), nullable=False)
    type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    target = Column(String(500), default="")
    evidence = Column(JSONB, default=dict)
    status = Column(String(30), default="new", server_default=text("'new'"))
    # ``dedup_key`` is unique *per application* (see uq_findings_app_dedup
    # below). Two apps may legitimately share the same CVE on the same
    # package version — making it globally unique broke trivy_fs upsert
    # the moment a second app inherited the same vulnerable dependency.
    dedup_key = Column(String(500), nullable=False, index=True)
    cve_id = Column(String(30), nullable=True)
    triaged_at = Column(DateTime(timezone=True), nullable=True)
    triaged_by = Column(String(255), nullable=True)
    triage_notes = Column(Text, default="")
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    application = relationship("Application", back_populates="findings")
    measure = relationship("Measure", back_populates="finding", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("application_id", "dedup_key", name="uq_findings_app_dedup"),
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_scanner", "scanner"),
        Index("ix_findings_app", "application_id"),
        Index("ix_findings_created", "created_at"),
    )


class Measure(Base):
    __tablename__ = "measures"
    id = Column(String(20), primary_key=True)
    # Primary finding (kept for backwards compat with the 1:1 relationship
    # on Finding). No longer unique since migration 002 — multiple measures
    # could technically share the same primary after future reassignment.
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    # All findings covered by this measure (set by bulk triage). Contains
    # at least finding_id after the migration 002 backfill.
    finding_ids = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    sort_order = Column(Integer, default=0)
    title = Column(String(500), default="")
    description = Column(Text, default="")
    statut = Column(String(30), default="a_faire")
    responsable = Column(String(255), default="")
    echeance = Column(String(50), default="")
    progress_log = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    finding = relationship("Finding", back_populates="measure")


class SBOMEntry(Base):
    __tablename__ = "sbom_entries"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id = Column(UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    package_name = Column(String(255), nullable=False)
    version = Column(String(100), default="")
    ecosystem = Column(String(50), default="")
    license = Column(String(500), default="")
    direct = Column(Boolean, default=True)
    parent_packages = Column(JSONB, default=list)
    depends_on = Column(JSONB, default=list)
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    application = relationship("Application", back_populates="sbom_entries")

    __table_args__ = (
        Index("ix_sbom_app_pkg", "application_id", "package_name", "version", unique=True),
    )


# ── Audit Log ─────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    logged_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    user_email = Column(String(255), nullable=False, default="")
    user_name = Column(String(255), nullable=True, default="")
    action = Column(String(100), nullable=False)         # e.g. "finding.triage", "app.create", "scan.trigger"
    target = Column(String(500), nullable=True, default="")  # what was acted on (app name, finding id, etc.)
    details = Column(Text, nullable=True, default="")    # free-form context (JSON or text)
    ip_address = Column(String(64), nullable=True, default="")

    __table_args__ = (
        Index("ix_audit_log_logged_at", "logged_at"),
        Index("ix_audit_log_user", "user_email"),
        Index("ix_audit_log_action", "action"),
    )


# ── Ignore Rules ──────────────────────────────────────────────────
class IgnoreRule(Base):
    __tablename__ = "ignore_rules"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Empty list = applies to all applications; else scoped to listed app IDs.
    application_ids = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    # Criteria are ANDed — ALL must match for a finding to be ignored.
    # Shape: [{"type": "cve_id", "value": "CVE-2024-*"}, {"type": "severity", "value": "info"}]
    # Supported types: cve_id, package, scanner_rule, target_pattern, severity
    criteria = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    reason = Column(Text, nullable=False)  # mandatory justification
    enabled = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    created_by = Column(String(255), nullable=True, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    __table_args__ = (
        Index("ix_ignore_rules_enabled", "enabled"),
    )


class DigestRun(Base):
    """FEAT-35 — notification send journal (Watch/Pilot pattern). Unique
    (recipient, kind, period_key) makes alert and weekly sends idempotent."""
    __tablename__ = "digest_runs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    recipient = Column(String(320), nullable=False)
    kind = Column(String(10), nullable=False)          # alert | weekly
    period_key = Column(String(64), nullable=False)    # scan_job id | ISO week
    sent_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(String(20), nullable=False)
    items_count = Column(Integer, default=0, server_default=text("0"))
    error_message = Column(Text, default="", server_default=text("''"))
    body_html = Column(Text, default="", server_default=text("''"))

    __table_args__ = (
        UniqueConstraint("recipient", "kind", "period_key",
                         name="uq_digest_runs_recipient_period"),
    )


class NotificationPrefs(Base):
    """FEAT-35 — LOCAL per-user prefs, used only when Pilot is absent
    (standalone). In suite mode the bell proxies Pilot's storage."""
    __tablename__ = "notification_prefs"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    lang = Column(String(5), nullable=False, default="fr", server_default=text("'fr'"))
    module_prefs = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    updated_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
