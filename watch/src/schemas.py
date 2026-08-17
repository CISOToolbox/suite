"""Pydantic schemas for the Watch module.

Phase 0 ships only the User + AI runtime schemas so the standard
routes (users, ai, audit) can import what they need. Phases 1+ add
Watch-specific schemas (Scope, ScopeRecipient, WatchTarget, Alert,
AlertStatus, DigestSettings…) right below the "Watch-specific" marker.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


# ── Standard suite schemas ───────────────────────────────────────
class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str
    picture: str
    role: str
    ai_enabled: str
    last_login: datetime | None
    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    role: str | None = None
    ai_enabled: str | None = None


# ── AI proxy schemas (used by src/routes/ai.py) ──────────────────
class AICompleteRequest(BaseModel):
    system: str
    user: str
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"


class AICompleteResponse(BaseModel):
    text: str


class AIConfigResponse(BaseModel):
    anthropic_configured: bool
    openai_configured: bool
    gemini_configured: bool = False
    providers: dict[str, dict[str, Any]]


class AIRuntimeResponse(BaseModel):
    managed: bool
    can_use: bool
    provider: str
    model: str
    anthropic_configured: bool
    openai_configured: bool
    gemini_configured: bool = False
    custom_configured: bool = False


# ── Watch-specific schemas — Phase 1: scopes + recipients ────────
from pydantic import Field, field_validator


_SEVERITY_VALUES = ("critical", "high", "medium", "low", "unknown")


# Threat-digest cadence — independent from the vulnerability digest
# (M14/M18). ``off`` shuts the threat digest down completely so a
# scope can opt out without disabling vuln alerts.
_THREAT_DIGEST_FREQUENCIES = ("off", "daily", "weekly")


class ScopeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=10000)
    digest_enabled: bool = True
    digest_hour: int = Field(7, ge=0, le=23)
    digest_minute: int = Field(0, ge=0, le=59)
    digest_timezone: str = Field("Europe/Paris", max_length=64)
    digest_severity_min: str = Field("critical", pattern="^(critical|high|medium|low|unknown)$")
    digest_include_kev: bool = True
    digest_cvss_min: float | None = Field(None, ge=0.0, le=10.0)
    digest_epss_min: float | None = Field(None, ge=0.0, le=1.0)
    # ── Threat digest cadence + free-prompt context (M22) ──────────
    threat_digest_enabled: bool = True
    threat_digest_frequency: str = Field("weekly", pattern="^(off|daily|weekly)$")
    threat_digest_weekday: int = Field(0, ge=0, le=6)
    threat_digest_hour: int = Field(8, ge=0, le=23)
    threat_digest_minute: int = Field(0, ge=0, le=59)
    threat_digest_timezone: str = Field("Europe/Paris", max_length=64)
    # Free-form CISO prompt sent to Claude (with web_search tool) at
    # digest time. Empty string = threat digest disabled for this scope.
    threat_prompt: str = Field("", max_length=10000)
    threat_search_window_days: int = Field(7, ge=1, le=30)


class ScopeUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=10000)
    digest_enabled: bool | None = None
    digest_hour: int | None = Field(None, ge=0, le=23)
    digest_minute: int | None = Field(None, ge=0, le=59)
    digest_timezone: str | None = Field(None, max_length=64)
    digest_severity_min: str | None = Field(None, pattern="^(critical|high|medium|low|unknown)$")
    digest_include_kev: bool | None = None
    # Use the sentinel float for "clear the gate" because Pydantic
    # collapses missing vs explicit-null both to None in a PATCH body.
    # Callers pass -1.0 to explicitly disable; any value in [0,10] sets
    # the gate; null/missing leaves the existing value untouched.
    digest_cvss_min: float | None = Field(None, ge=-1.0, le=10.0)
    digest_epss_min: float | None = Field(None, ge=-1.0, le=1.0)
    threat_digest_enabled: bool | None = None
    threat_digest_frequency: str | None = Field(None, pattern="^(off|daily|weekly)$")
    threat_digest_weekday: int | None = Field(None, ge=0, le=6)
    threat_digest_hour: int | None = Field(None, ge=0, le=23)
    threat_digest_minute: int | None = Field(None, ge=0, le=59)
    threat_digest_timezone: str | None = Field(None, max_length=64)
    threat_prompt: str | None = Field(None, max_length=10000)
    threat_search_window_days: int | None = Field(None, ge=1, le=30)


class ScopeRecipientResponse(BaseModel):
    email: str
    name: str
    added_at: datetime
    added_by_email: str
    model_config = {"from_attributes": True}


class ScopeRecipientAdd(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    name: str = Field("", max_length=255)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or v.count("@") != 1:
            raise ValueError("invalid email")
        local, _, domain = v.partition("@")
        if not local or not domain or "." not in domain:
            raise ValueError("invalid email")
        return v


class ScopeResponse(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    owner_email: str = ""
    name: str
    description: str
    digest_enabled: bool = True
    digest_hour: int = 7
    digest_minute: int = 0
    digest_timezone: str = "Europe/Paris"
    digest_severity_min: str = "critical"
    digest_include_kev: bool = True
    digest_cvss_min: float | None = None
    digest_epss_min: float | None = None
    # ── Threat digest cadence + free-prompt (M22) ──────────────────
    threat_digest_enabled: bool = True
    threat_digest_frequency: str = "weekly"
    threat_digest_weekday: int = 0
    threat_digest_hour: int = 8
    threat_digest_minute: int = 0
    threat_digest_timezone: str = "Europe/Paris"
    threat_prompt: str = ""
    threat_search_window_days: int = 7
    created_at: datetime
    updated_at: datetime
    recipients: list[ScopeRecipientResponse] = []
    is_owner: bool = False
    model_config = {"from_attributes": True}


# ThreatTopic* / ThreatMigration* / ThreatTheme schemas removed in M22 —
# the free-prompt threat digest stores its context inline on the Scope
# and has no separate topics / themes / migration concepts.


# ── Watch-specific schemas — Phase 2: watch targets ──────────────

class WatchTargetCreate(BaseModel):
    kind: str = Field(..., pattern="^(cpe|purl|keyword)$")
    value: str = Field(..., min_length=2, max_length=500)
    label: str = Field("", max_length=200)
    version_constraint: str = Field("", max_length=100)
    notes: str = Field("", max_length=5000)
    enabled: bool = True

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class WatchTargetUpdate(BaseModel):
    label: str | None = Field(None, max_length=200)
    version_constraint: str | None = Field(None, max_length=100)
    notes: str | None = Field(None, max_length=5000)
    enabled: bool | None = None


class WatchTargetResponse(BaseModel):
    id: uuid.UUID
    scope_id: uuid.UUID
    kind: str
    value: str
    label: str
    version_constraint: str
    notes: str
    enabled: bool
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


# ── Watch-specific schemas — Phase 3: alerts + matches + statuses ─

class AlertMatchResponse(BaseModel):
    target_id: uuid.UUID
    scope_id: uuid.UUID
    match_kind: str
    match_value: str
    matched_at: datetime
    # Display-only fields hydrated by the route for the frontend.
    target_label: str = ""
    scope_name: str = ""
    model_config = {"from_attributes": True}


class AlertResponse(BaseModel):
    id: uuid.UUID
    source: str
    external_id: str
    title: str
    summary: str
    severity: str
    cvss_score: float | None
    cvss_vector: str
    epss_score: float | None
    kev_listed: bool
    published_at: datetime | None
    modified_at: datetime | None
    references_json: list[Any] = []
    affected_json: list[Any] = []
    ingested_at: datetime
    # Hydrated by routes:
    status: str = "new"
    note: str = ""
    matches: list[AlertMatchResponse] = []
    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(new|ack|in_progress|dismissed|resolved)$")
    note: str = Field("", max_length=5000)


class AlertBulkStatusUpdate(BaseModel):
    ids: list[uuid.UUID] = Field(..., min_length=1, max_length=500)
    status: str = Field(..., pattern="^(new|ack|in_progress|dismissed|resolved)$")
    note: str = Field("", max_length=5000)


class AlertAnalysisResponse(BaseModel):
    alert_id: uuid.UUID
    content_hash: str
    sections: dict[str, Any] = {}
    provider: str
    model: str
    generated_at: datetime
    model_config = {"from_attributes": True}


class FeedStateResponse(BaseModel):
    source: str
    last_sync_at: datetime | None
    last_success_at: datetime | None
    last_cursor: str
    last_error: str
    next_due_at: datetime | None
    items_seen: int          # last batch — number of candidates streamed
    items_new: int           # last batch — number of new alerts persisted
    total_in_db: int = 0     # cumulative — total alerts persisted from this source
    enabled: bool
    model_config = {"from_attributes": True}

