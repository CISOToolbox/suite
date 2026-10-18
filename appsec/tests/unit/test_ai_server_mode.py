"""FEAT-58 — a standalone module runs its AI on its own server.

The shared AI router (``src/ai_proxy_common.py``), against SQLite. Locks:
  - standalone: the runtime says the server owns the AI (``managed``, by the
    module), editable by its admin only — every provider then works, the
    browser never holds a key;
  - suite (``AI_MANAGED_BY_PILOT``): Pilot's, read-only; a write without the
    service token is refused with 409;
  - the module's admin sets provider, model and keys: a secret left out is
    kept, an empty one clears it, a value replaces it; secrets are encrypted
    at rest and never read back;
  - a Bedrock region and a custom endpoint are checked when saved;
  - a non-admin cannot write.
"""
from __future__ import annotations

import os
import socket
import sys
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/appsec_test")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import ai_proxy_common, auth_common  # noqa: E402
from src.database import get_db  # noqa: E402
from src.models import AppSettings  # noqa: E402
from src.settings_crypto import is_encrypted  # noqa: E402

_FAKE_DNS = {"llm.medsecure.example": "93.184.216.34"}
_real_getaddrinfo = socket.getaddrinfo


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    def getaddrinfo(host, *args, **kwargs):
        if host in _FAKE_DNS:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_FAKE_DNS[host], 0))]
        return _real_getaddrinfo(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest_asyncio.fixture
async def sessions():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def make_client(monkeypatch, sessions):
    async def _db():
        async with sessions() as s:
            yield s

    def _make(suite: bool = False, role: str | None = "admin", service_token: bool = False):
        monkeypatch.setattr(auth_common, "AUTH_MODE", "pilot" if suite else "standalone")
        monkeypatch.setenv("AI_MANAGED_BY_PILOT", "true" if suite else "false")
        monkeypatch.setenv("SERVICE_TOKEN", "a-service-token")
        user = None if role is None else SimpleNamespace(id="u-1", role=role, ai_enabled="false",
                                                         _module_role=role)

        # PUT /api/ai/keys calls it directly (service token or user): replace
        # it where the router reads it, before building the router.
        async def current_user(request: Request, db: AsyncSession = Depends(get_db)):
            return user
        monkeypatch.setattr(ai_proxy_common, "get_current_user", current_user)
        app = FastAPI()
        app.include_router(ai_proxy_common.make_ai_router())
        app.dependency_overrides[get_db] = _db
        headers = {"X-Service-Token": "a-service-token"} if service_token else {}
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=headers)

    return _make, sessions


async def _rows(sessions) -> dict[str, str]:
    async with sessions() as s:
        return {r.key: r.value for r in (await s.execute(select(AppSettings))).scalars()}


@pytest.mark.asyncio
async def test_standalone_the_module_runs_its_ai_and_its_admin_sets_it(make_client):
    make, _ = make_client
    async with make() as c:
        r = (await c.get("/api/ai/runtime")).json()
    assert r["managed"] is True and r["managed_by"] == "module" and r["editable"] is True
    async with make(role="viewer") as c:
        r = (await c.get("/api/ai/runtime")).json()
    assert r["managed_by"] == "module" and r["editable"] is False
    async with make(role=None) as c:     # authentication disabled: the caller is the admin
        assert (await c.get("/api/ai/runtime")).json()["editable"] is True


@pytest.mark.asyncio
async def test_in_the_suite_the_ai_is_pilots(make_client):
    make, sessions = make_client
    async with make(suite=True) as c:
        r = (await c.get("/api/ai/runtime")).json()
        assert r["managed_by"] == "pilot" and r["editable"] is False
        assert (await c.put("/api/ai/keys", json={"anthropic": "sk-ant"})).status_code == 409
    assert await _rows(sessions) == {}
    async with make(suite=True, role=None, service_token=True) as c:   # Pilot's push
        assert (await c.put("/api/ai/keys", json={"anthropic": "sk-ant"})).status_code == 200


@pytest.mark.asyncio
async def test_a_secret_left_out_is_kept_an_empty_one_cleared(make_client):
    make, sessions = make_client
    async with make() as c:
        assert (await c.put("/api/ai/keys", json={"provider": "bedrock", "model": "anthropic.claude-sonnet-5",
                                                    "bedrock": "AKIA-demo", "ai_secret_bedrock": "s3cret",
                                                    "ai_region_bedrock": "eu-west-3"})).status_code == 200
        rows = await _rows(sessions)
        assert is_encrypted(rows["ai_key_bedrock"]) and is_encrypted(rows["ai_secret_bedrock"])
        assert (await c.put("/api/ai/keys", json={"ai_region_bedrock": "eu-central-1"})).status_code == 200
        keys = (await c.get("/api/ai/keys")).json()
        assert keys["bedrock"] == "configured" and keys["ai_secret_bedrock"] == "configured"
        assert keys["ai_region_bedrock"] == "eu-central-1" and keys["provider"] == "bedrock"
        assert "s3cret" not in str(keys) and "AKIA-demo" not in str(keys)
        assert (await c.put("/api/ai/keys", json={"ai_secret_bedrock": ""})).status_code == 200
        assert (await c.get("/api/ai/keys")).json()["ai_secret_bedrock"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"ai_region_bedrock": "eu-west-3.evil.example/"},
    {"ai_custom_endpoint": "http://llm.medsecure.example/v1"},       # not https
    {"ai_custom_endpoint": "https://127.0.0.1/v1"},
    {"ai_custom_endpoint": "https://169.254.169.254/latest"},
    {"provider": "unknown"},
])
async def test_what_is_saved_is_checked(make_client, body):
    make, sessions = make_client
    async with make() as c:
        r = await c.put("/api/ai/keys", json=body)
    assert r.status_code == 400, r.text
    assert await _rows(sessions) == {}


@pytest.mark.asyncio
async def test_a_custom_endpoint_is_accepted_and_reported(make_client):
    make, _ = make_client
    async with make() as c:
        r = await c.put("/api/ai/keys", json={"provider": "custom", "ai_custom_endpoint": "https://llm.medsecure.example/v1",
                                               "ai_custom_model": "medsecure-llm", "ai_custom_key": "ck"})
        assert r.status_code == 200, r.text
        keys = (await c.get("/api/ai/keys")).json()
    assert keys["ai_custom_endpoint"] == "https://llm.medsecure.example/v1" and keys["ai_custom_key"] == "configured"


@pytest.mark.asyncio
async def test_a_non_admin_cannot_write(make_client):
    make, sessions = make_client
    async with make(role="viewer") as c:
        assert (await c.put("/api/ai/keys", json={"anthropic": "sk-ant"})).status_code == 403
    assert await _rows(sessions) == {}


@pytest.mark.asyncio
async def test_without_ai_managed_by_pilot_a_suite_module_keeps_the_browser_flow(make_client, monkeypatch):
    make, _ = make_client
    async with make(suite=True) as c:
        monkeypatch.setenv("AI_MANAGED_BY_PILOT", "false")
        r = (await c.get("/api/ai/runtime")).json()
    assert r["managed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "https://llm.only-the-proxy-resolves.example/v1",   # behind an outbound proxy
    "http://llm.medsecure.example/v1",                 # Pilot allows http when its operator opts in
])
async def test_pilot_s_push_is_stored_as_pilot_checked_it(make_client, monkeypatch, endpoint):
    make, sessions = make_client
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.medsecure.example:3128")
    async with make(suite=True, role=None, service_token=True) as c:
        r = await c.put("/api/ai/keys", json={"anthropic": "sk-ant-new", "ai_custom_endpoint": endpoint})
    assert r.status_code == 200, r.text
    assert "ai_key_anthropic" in await _rows(sessions)


@pytest.mark.asyncio
async def test_the_admin_s_custom_endpoint_is_checked_as_the_call_checks_it(make_client, monkeypatch):
    """Behind an outbound proxy, the proxy resolves the name — at save as at call."""
    make, _ = make_client
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.medsecure.example:3128")
    async with make() as c:
        r = await c.put("/api/ai/keys", json={"provider": "custom",
                                               "ai_custom_endpoint": "https://llm.only-the-proxy-resolves.example/v1"})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_without_encryption_key_keys_are_kept_in_clear(make_client, monkeypatch):
    """A standalone module may run without ENCRYPTION_KEY (documented): the
    save must not fail."""
    from src import settings_crypto
    make, sessions = make_client
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr(settings_crypto, "_KEY", None)
    async with make() as c:
        r = await c.put("/api/ai/keys", json={"provider": "anthropic", "anthropic": "sk-ant-plain"})
    assert r.status_code == 200, r.text
    assert (await _rows(sessions))["ai_key_anthropic"] == "sk-ant-plain"


@pytest.mark.asyncio
async def test_settings_are_stored_as_they_were_checked(make_client):
    make, _ = make_client
    async with make() as c:
        r = await c.put("/api/ai/keys", json={"provider": "custom",
                                               "ai_custom_endpoint": "  https://llm.medsecure.example/v1  "})
        assert r.status_code == 200, r.text
        assert (await c.get("/api/ai/keys")).json()["ai_custom_endpoint"] == "https://llm.medsecure.example/v1"
