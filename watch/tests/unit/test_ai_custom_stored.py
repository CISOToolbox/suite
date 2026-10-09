"""BUG-92 — the custom LLM Pilot sends with the AI keys survives a restart.

Pilot pushes the custom LLM twice: to ``PUT /api/internal/ai-custom``, held in
memory, and with the AI keys to ``PUT /api/ai/keys``, stored in
``app_settings``. ``_get_custom_llm`` reads the stored copy once a restart has
emptied the in-memory one; the label was not stored, so it came back as
"Custom LLM". Locks, against SQLite through the keys route: endpoint, key,
model and label stored by the push are the config used after a restart.
"""
from __future__ import annotations

import os
import sys

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/watch_test")
os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.database import get_db  # noqa: E402
from src.models import AppSettings, AuditLog  # noqa: E402
from src.routes import ai  # noqa: E402

_TOKEN = "svc-token-for-tests-0123456789abcdef"
_MISTRAL = {"endpoint": "https://api.mistral.ai/v1", "model": "mistral-small-latest",
            "key": "medsecure-llm-key", "label": "MedSecure LLM"}


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
        await c.run_sync(AuditLog.__table__.create)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_stored_custom_llm_survives_a_restart(db, monkeypatch):
    import src.routes.internal as internal
    monkeypatch.setenv("SERVICE_TOKEN", _TOKEN)
    app = FastAPI()
    app.include_router(ai.router)
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://watch") as c:
        resp = await c.put("/api/ai/keys", headers={"X-Service-Token": _TOKEN}, json={
            "ai_custom_endpoint": _MISTRAL["endpoint"], "ai_custom_key": _MISTRAL["key"],
            "ai_custom_model": _MISTRAL["model"], "ai_custom_label": _MISTRAL["label"]})
    assert resp.status_code == 200
    monkeypatch.setattr(internal, "_custom_llm", {})  # what a restart leaves in memory
    assert await ai._get_custom_llm(db) == _MISTRAL

@pytest.mark.asyncio
async def test_settings_cleared_in_pilot_are_cleared_in_the_module(db, monkeypatch):
    import src.routes.internal as internal
    monkeypatch.setenv("SERVICE_TOKEN", _TOKEN)
    monkeypatch.setattr(internal, "SERVICE_TOKEN", _TOKEN, raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(internal, "_custom_llm", {})
    app = FastAPI()
    app.include_router(ai.router)
    app.include_router(internal.router)
    app.dependency_overrides[get_db] = lambda: db
    headers = {"X-Service-Token": _TOKEN}
    full = {"openai": "sk-medsecure", "ai_custom_endpoint": _MISTRAL["endpoint"], "ai_custom_key": _MISTRAL["key"],
            "ai_custom_model": _MISTRAL["model"], "ai_custom_label": _MISTRAL["label"]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://module") as c:
        assert (await c.put("/api/ai/keys", headers=headers, json=full)).status_code == 200
        assert (await c.put("/api/ai/keys", headers=headers, json={k: "" for k in full})).status_code == 200
        assert (await c.put("/api/internal/ai-custom", headers=headers,
                            json={"endpoint": "", "model": "", "key": "", "label": ""})).status_code == 200
        for _ in range(2):  # as pushed, then after a restart (memory empty)
            custom = await ai._get_custom_llm(db)
            assert (custom.get("endpoint", ""), custom.get("key", "")) == ("", "")
            assert not await ai._get_api_key("openai", db)
            monkeypatch.setattr(internal, "_custom_llm", {})

