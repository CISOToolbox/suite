from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str | None
    picture: str | None
    provider: str
    role: str
    modules: list[str]
    permissions: dict[str, str] = {}
    ai_enabled: str
    created_at: datetime
    last_login: datetime | None
    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    role: str | None = None
    modules: list[str] | None = None
    permissions: dict[str, str] | None = None
    ai_enabled: str | None = None


class ModuleInfo(BaseModel):
    id: str
    name: str
    external_url: str
    status: str
    model_config = {"from_attributes": True}


class DashboardModule(BaseModel):
    id: str
    name: str
    url: str
    status: str
    stats: dict[str, Any] | None = None
    last_sync: datetime | None = None


class DashboardResponse(BaseModel):
    modules: list[DashboardModule]
    measures_summary: dict[str, Any]


class MeasureItem(BaseModel):
    id: str
    module: str
    source_id: str
    entity_name: str | None
    title: str
    status: str
    assignee: str | None
    due_date: str | None
    type: str | None
    source_module: str | None
    model_config = {"from_attributes": True}


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
    providers: dict[str, dict[str, Any]]
