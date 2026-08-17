from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, SmallInteger,
    String, Text, Index, text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# ── Standard suite tables (shared shape across all modules) ──────
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
    # Digest preferences are stored per-scope (see Scope.digest_*).
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)


class AppSettings(Base):
    __tablename__ = "app_settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    logged_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    user_email = Column(String(255), nullable=False, default="")
    user_name = Column(String(255), nullable=True, default="")
    action = Column(String(100), nullable=False)
    target = Column(String(500), nullable=True, default="")
    details = Column(Text, nullable=True, default="")
    ip_address = Column(String(64), nullable=True, default="")

    __table_args__ = (
        Index("ix_audit_log_logged_at", "logged_at"),
        Index("ix_audit_log_user", "user_email"),
        Index("ix_audit_log_action", "action"),
    )


from sqlalchemy import UniqueConstraint

# ── Watch-specific tables ────────────────────────────────────────
# Phase 1: Scope, ScopeRecipient.
# Phase 2: WatchTarget.
# Later phases will add: Alert, AlertMatch, AlertStatus, AlertAnalysis,
# DigestRun, FeedState, CPEDictEntry.

class Scope(Base):
    """A logical grouping of monitored technologies, owned by one user.

    Each owner can attach recipients (by email) who receive the daily
    digest for this scope. The owner is identified by their watch.users.id
    (the user is necessarily logged in to create a scope). Recipients are
    keyed by email so that pre-provisioning works even before they have
    logged in to Watch for the first time.
    """
    __tablename__ = "scopes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(200), nullable=False)
    description = Column(Text, default="", server_default="")
    # Per-scope digest preferences (Option A — all recipients of this scope
    # receive the digest at the scope's local time; recipients have no
    # global override). Stored as integer hour/minute + IANA timezone so
    # the scheduler can convert to UTC at send time.
    digest_enabled = Column(Boolean, default=True, server_default=text("true"), nullable=False)
    digest_hour = Column(Integer, default=7, server_default=text("7"), nullable=False)
    digest_minute = Column(Integer, default=0, server_default=text("0"), nullable=False)
    digest_timezone = Column(String(64), default="Europe/Paris", server_default=text("'Europe/Paris'"), nullable=False)
    # Digest v2: per-scope severity thresholds. A vuln passes the filter
    # if ANY of these match: severity >= digest_severity_min, OR
    # kev_listed AND digest_include_kev, OR cvss_score >= digest_cvss_min,
    # OR epss_score >= digest_epss_min. nullable cvss/epss → that gate off.
    digest_severity_min = Column(String(20), default="critical",
                                 server_default=text("'critical'"), nullable=False)
    digest_include_kev = Column(Boolean, default=True,
                                server_default=text("true"), nullable=False)
    digest_cvss_min = Column(Float, nullable=True)
    digest_epss_min = Column(Float, nullable=True)
    # ── Threat digest (M22 — free-prompt mode):
    # Instead of a structured topics-and-keywords pipeline, the scope owner
    # writes one paragraph of context (sector, stack, sensitivities) in
    # ``threat_prompt``. At digest time we send the prompt to Claude with
    # the Anthropic web_search tool enabled and a window of
    # ``threat_search_window_days`` days; Claude produces a synthesized
    # CTI brief covering the window. Empty ``threat_prompt`` disables the
    # threat section entirely (no digest sent).
    # ``threat_digest_frequency`` ∈ {"daily", "weekly", "off"}. ``daily``
    # mirrors the vuln digest (hour/minute/timezone). ``weekly`` adds
    # ``threat_digest_weekday`` (0=Monday).
    threat_digest_enabled = Column(Boolean, default=True,
                                   server_default=text("true"), nullable=False)
    threat_digest_frequency = Column(String(20), default="weekly",
                                     server_default=text("'weekly'"), nullable=False)
    threat_digest_weekday = Column(Integer, default=0,
                                   server_default=text("0"), nullable=False)
    threat_digest_hour = Column(Integer, default=8,
                                server_default=text("8"), nullable=False)
    threat_digest_minute = Column(Integer, default=0,
                                  server_default=text("0"), nullable=False)
    threat_digest_timezone = Column(String(64), default="Europe/Paris",
                                    server_default=text("'Europe/Paris'"), nullable=False)
    threat_prompt = Column(Text, default="",
                           server_default=text("''"), nullable=False)
    threat_search_window_days = Column(Integer, default=7,
                                       server_default=text("7"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class ScopeRecipient(Base):
    """Email-based recipient list for a scope.

    Composite primary key (scope_id, email). `name` is a display snapshot
    refreshed when the recipient is (re)added; the digest worker uses
    `email` directly to send the daily summary. `added_by_email` records
    who added the recipient (typically the scope owner) for audit clarity.
    """
    __tablename__ = "scope_recipients"

    scope_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scopes.id", ondelete="CASCADE"),
        primary_key=True,
    )
    email = Column(String(320), primary_key=True)
    name = Column(String(255), default="", server_default="")
    added_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    added_by_email = Column(String(320), default="", server_default="")


class WatchTarget(Base):
    """A technology to monitor within a scope.

    Three identification kinds are supported (validated step 5):
      - "cpe"     : NVD canonical CPE 2.3 (e.g. cpe:2.3:a:openssl:openssl:*)
                    Used for direct CVE matching against NVD/CISA KEV.
      - "purl"    : Package URL spec (e.g. pkg:npm/lodash, pkg:pypi/django)
                    Used for OSV.dev / GHSA matching.
      - "keyword" : free-text label (vendor name, product, technology family)
                    Used for general advisories (CERT-FR, vendor blogs,
                    supply-chain compromise alerts).

    `version_constraint` is an optional semver-style restriction
    ("<2.4.0", ">=1.0.0,<2.0.0", "*", …). When empty, every published
    version is in scope.
    """
    __tablename__ = "watch_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scopes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind = Column(String(20), nullable=False)  # "cpe" | "purl" | "keyword"
    value = Column(String(500), nullable=False)
    label = Column(String(200), default="", server_default="")
    version_constraint = Column(String(100), default="", server_default="")
    notes = Column(Text, default="", server_default="")
    enabled = Column(Boolean, default=True, server_default=text("true"))
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("scope_id", "kind", "value", name="uq_targets_scope_kind_value"),
    )


# ThreatTopic + ThreatMatch were removed in migration 012 (M22 — free-prompt
# threat digest). The scope's ``threat_prompt`` + ``threat_search_window_days``
# fields replace them entirely; at digest time the prompt is handed to Claude
# with the Anthropic web_search tool. No persistent matches are stored — the
# rendered HTML in ``DigestRun.body_html`` is the audit trail.


# ── Phase 3: alerts + matches + per-user statuses + feed bookkeeping ──

class Alert(Base):
    """A single vulnerability or advisory record ingested from a feed.

    `external_id` is the canonical identifier within `source` (CVE-2025-1234
    for NVD, GHSA-xxx for GHSA, CERTFR-2025-CTI-001 for CERT-FR…). The
    (source, external_id) tuple is unique so the same advisory ingested
    twice updates the existing row instead of duplicating.

    `affected_json` is a normalised list of {cpe?, purl?, vendor?, product?,
    version_range?} entries built by the feed adapter, consumed by the
    matcher (phase 4) to compute AlertMatch rows.

    `raw_json` is the original feed record kept for traceability and for
    the LLM analysis prompt (phase 5).
    """
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(50), nullable=False)
    external_id = Column(String(200), nullable=False)
    title = Column(String(500), nullable=False, default="")
    summary = Column(Text, default="", server_default="")
    severity = Column(String(20), default="unknown", server_default="'unknown'")
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), default="", server_default="")
    epss_score = Column(Float, nullable=True)
    kev_listed = Column(Boolean, default=False, server_default=text("false"))
    kev_listed_at = Column(DateTime(timezone=True), nullable=True)  # when the KEV flip happened; NULL = listed before tracking (treated as historical by the digest)
    published_at = Column(DateTime(timezone=True), nullable=True)
    modified_at = Column(DateTime(timezone=True), nullable=True)
    references_json = Column(JSONB, default=list)
    affected_json = Column(JSONB, default=list)
    raw_json = Column(JSONB, default=dict)
    ingested_at = Column(DateTime(timezone=True), nullable=False,
                         default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_alerts_source_external"),
        Index("ix_alerts_published_at", "published_at"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_kev_listed", "kev_listed"),
    )


class AlertMatch(Base):
    """A WatchTarget that matched an Alert. Computed by the matcher."""
    __tablename__ = "alert_matches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id = Column(
        UUID(as_uuid=True),
        ForeignKey("watch_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scope_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scopes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    match_kind = Column(String(20), nullable=False)   # "cpe" | "purl" | "keyword" | "backfill" (retro-match at target creation)
    match_value = Column(String(500), nullable=False)
    matched_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("alert_id", "target_id", name="uq_match_alert_target"),
    )


class AlertStatus(Base):
    """Per-user triage state for an alert.

    Recipients and owners may each have their own status (the same
    alert can be "dismissed" by one recipient and still "new" for the
    owner). PK = (alert_id, user_id).
    """
    __tablename__ = "alert_statuses"

    alert_id = Column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    status = Column(String(20), nullable=False, default="new", server_default="'new'")
    note = Column(Text, default="", server_default="")
    updated_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))


class DigestRun(Base):
    """One row per (user × scope × calendar-date) digest sent.

    The scheduler uses the unique (user_email, scope_id, calendar_date)
    constraint to be idempotent — a daily tick that overlaps the
    target window twice still sends exactly one email per recipient.

    ``status`` is one of: pending, sent, skipped_empty, failed.
    """
    __tablename__ = "digest_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_email = Column(String(320), nullable=False, index=True)
    scope_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scopes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # "vuln" → driven by Scope.digest_*; "threat" → driven by
    # Scope.threat_digest_*. The two cadences are independent so a
    # vuln digest and a threat digest can both fire on the same day
    # without colliding on the (user, scope, date) idempotence key.
    kind = Column(String(10), nullable=False, default="vuln",
                  server_default=text("'vuln'"))
    calendar_date = Column(String(10), nullable=False)  # "YYYY-MM-DD" in user's TZ
    sent_at = Column(DateTime(timezone=True), nullable=False,
                     default=lambda: datetime.now(timezone.utc))
    status = Column(String(20), nullable=False, default="pending")
    alerts_count = Column(Integer, default=0, server_default="0")
    error_message = Column(Text, default="", server_default="")
    # Migration 013: rendered HTML body of the email actually sent (or
    # of the brief that would have been sent on failure). Empty string
    # on skipped_empty and on legacy rows from before the column existed.
    # Used by the frontend history view to replay a digest in an iframe.
    body_html = Column(Text, nullable=False, default="", server_default=text("''"))

    # Partial unique index (migration 011): only terminal statuses
    # (``sent``, ``failed``) participate in the per-day idempotence key.
    # ``skipped_empty`` rows do NOT block re-runs — see _already_sent_today
    # in digest.py for the rationale (proposal 2 from the 2026-05-14
    # bug report: a fresh scope whose matcher hadn't populated yet would
    # stamp skipped_empty and block the real digest for the rest of
    # the day).
    __table_args__ = (
        Index(
            "uq_digest_user_scope_kind_date_sent",
            "user_email", "scope_id", "kind", "calendar_date",
            unique=True,
            postgresql_where=text("status IN ('sent', 'failed')"),
        ),
    )


class AlertAnalysis(Base):
    """LLM-generated 8-section analysis for an alert.

    Cached by ``content_hash`` (sha256 of the alert fields that feed the
    prompt) so re-generating against an unchanged alert returns the
    cached row instantly. When the alert is updated (modified_at or
    severity bumps), the hash drifts and the next ``analyze`` call
    produces a fresh row that supersedes the old one.

    Sections (stored as JSONB ``sections``):
      - executive_summary
      - technical_detail
      - exploitation_status
      - affected_components
      - business_impact
      - recommended_actions
      - references_curated
      - confidence
    """
    __tablename__ = "alert_analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    content_hash = Column(String(64), nullable=False)
    language = Column(String(8), nullable=False,
                      server_default=text("'en'"), default="en")
    sections = Column(JSONB, default=dict)
    provider = Column(String(50), default="")
    model = Column(String(100), default="")
    generated_by_user_id = Column(UUID(as_uuid=True), nullable=True)
    generated_at = Column(DateTime(timezone=True), nullable=False,
                          default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("alert_id", "content_hash", "language",
                         name="uq_analysis_alert_hash_lang"),
    )


class FeedState(Base):
    """Per-feed sync bookkeeping for the scheduler.

    Keyed by `source` (string, same vocabulary as Alert.source). Stores
    the last successful pull timestamp + cursor so a delta fetch can
    resume from where the previous tick left off.
    """
    __tablename__ = "feed_state"

    source = Column(String(50), primary_key=True)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_cursor = Column(String(500), default="", server_default="")
    last_error = Column(Text, default="", server_default="")
    next_due_at = Column(DateTime(timezone=True), nullable=True)
    items_seen = Column(Integer, default=0, server_default="0")
    items_new = Column(Integer, default=0, server_default="0")
    enabled = Column(Boolean, default=True, server_default=text("true"))
