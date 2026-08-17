from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── User schemas ──────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str | None
    picture: str | None
    provider: str
    role: str
    ai_enabled: str
    created_at: datetime
    last_login: datetime | None

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    role: str | None = None
    ai_enabled: str | None = None


# ── Stored-audit schemas ─────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str = ""
    organization: str | None = None
    audit_date: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class ProjectUpdate(BaseModel):
    name: str | None = None
    organization: str | None = None
    audit_date: str | None = None
    data: dict[str, Any] | None = None
    # FEAT-33 stale-tab guard (see routes/projects.update_project).
    expected_server_rev: int | None = None


class ProjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    organization: str | None
    audit_date: str | None
    owner_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    server_rev: int = 0
    data: dict[str, Any]

    model_config = {"from_attributes": True}


class ProjectListItem(BaseModel):
    id: uuid.UUID
    name: str
    organization: str | None
    audit_date: str | None
    owner_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── AI schemas ───────────────────────────────────────────────────

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
