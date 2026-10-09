"""BUG-92 — what the settings push sends each module, and what it reports.

``_push_to_modules`` sends the custom LLM config to each module at
``PUT /api/internal/ai-custom`` and the proxy at ``PUT /api/internal/proxy``,
and returns a per-module report, shown by "Resync modules". The status of
those calls was never read: a module without the route (Surface answered 405)
was reported "ok" while it never received the config. And the custom LLM
lived only in the module's memory, so a module restart lost it until someone
re-synced. Locks, against SQLite with the modules replaced by a transport:
  - every module accepting the push is "ok";
  - a module refusing the custom LLM or the proxy is reported with the failed
    call, and the pushes that follow it still reach that module;
  - the custom LLM also goes with the AI keys, which the module stores, so it
    survives a restart, label included; clearing it in Pilot clears it in
    both places;
  - every provider key goes with each push, so a key cleared in Pilot is
    cleared in the module (absent, it stayed there for ever).
  - so do the three proxy fields: the module stores the proxy, and one
    cleared in Pilot would otherwise come back at every module start;
  - and the provider, model and Bedrock region: Pilot is authoritative;
  - a secret Pilot cannot decrypt (ENCRYPTION_KEY changed) reads back as "":
    it is not sent, so it never blanks the modules' copy, and the report says
    so for every module.
"""
import json
import os
import sys

import httpx
import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.models import AppSettings, Base, ModuleRegistry  # noqa: E402
from src.routes import settings  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb", "false", "true")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add_all([
            ModuleRegistry(id="surface", name="Surface", internal_url="http://surface:8000", external_url="/surface/"),
            ModuleRegistry(id="risk", name="Risk", internal_url="http://risk:8000", external_url="/risk/"),
            AppSettings(key="ai_custom_endpoint", value="https://llm.medsecure.example/v1"),
            AppSettings(key="ai_custom_model", value="medsecure-llm"),
            AppSettings(key="ai_custom_label", value="MedSecure LLM"),
            AppSettings(key="http_proxy", value="http://proxy.medsecure.example:3128"),
        ])
        await session.commit()
        yield session
    await engine.dispose()


def _modules(monkeypatch, refusing: set[tuple[str, str]] | None = None,
             missing: set[tuple[str, str]] | None = None,
             failing: set[tuple[str, str]] | None = None) -> list[tuple[str, str, dict]]:
    """Every module accepts every push, except the (host, route) pairs in
    `refusing`, answered 405, in `missing`, answered 404 (both are what a
    module without the route answers), and in `failing`, answered 500."""
    refusing = refusing or set()
    missing = missing or set()
    failing = failing or set()
    seen: list[tuple[str, str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.url.path, json.loads(request.content or b"{}")))
        route = request.url.path.removeprefix("/api/internal/")
        if (request.url.host, route) in refusing:
            return httpx.Response(405, json={"detail": "Method Not Allowed"})
        if (request.url.host, route) in missing:
            return httpx.Response(404, json={"detail": "Not Found"})
        if (request.url.host, route) in failing:
            return httpx.Response(500, json={"detail": "Internal Server Error"})
        if request.url.path == "/api/connectors":
            return httpx.Response(404)
        return httpx.Response(200, json={"ok": True})

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}))
    return seen


def _sent(seen, host: str, path: str) -> dict:
    [body] = [b for h, p, b in seen if h == host and p == path]
    return body


@pytest.mark.asyncio
async def test_modules_accepting_the_push_are_ok(db, monkeypatch):
    _modules(monkeypatch, refusing=set())
    assert await settings._push_to_modules(db) == {"surface": "ok", "risk": "ok"}


@pytest.mark.asyncio
async def test_a_module_refusing_the_custom_llm_is_reported(db, monkeypatch):
    seen = _modules(monkeypatch, refusing={("surface", "ai-custom")})
    report = await settings._push_to_modules(db)
    assert report == {"surface": "ai_custom: HTTP 405", "risk": "ok"}
    assert any(h == "surface" and p == "/api/internal/proxy" for h, p, _ in seen)


@pytest.mark.asyncio
async def test_a_module_refusing_the_proxy_is_reported(db, monkeypatch):
    _modules(monkeypatch, refusing={("surface", "proxy"), ("risk", "ai-custom"), ("risk", "proxy")})
    report = await settings._push_to_modules(db)
    assert report == {"surface": "proxy: HTTP 405", "risk": "ai_custom: HTTP 405; proxy: HTTP 405"}


@pytest.mark.asyncio
async def test_the_custom_llm_is_stored_by_the_module(db, monkeypatch):
    seen = _modules(monkeypatch)
    await settings._push_to_modules(db)
    keys = _sent(seen, "surface", "/api/ai/keys")
    assert (keys["ai_custom_endpoint"], keys["ai_custom_model"], keys["ai_custom_label"]) == (
        "https://llm.medsecure.example/v1", "medsecure-llm", "MedSecure LLM")
    assert "ai_custom_key" in keys


@pytest.mark.asyncio
async def test_clearing_the_custom_llm_clears_it_in_the_module(db, monkeypatch):
    from sqlalchemy import delete
    await db.execute(delete(AppSettings).where(AppSettings.key.like("ai_custom_%")))
    await db.commit()
    seen = _modules(monkeypatch)
    await settings._push_to_modules(db)
    keys = _sent(seen, "surface", "/api/ai/keys")
    assert {k: keys[k] for k in ("ai_custom_endpoint", "ai_custom_key", "ai_custom_model", "ai_custom_label")} == {
        "ai_custom_endpoint": "", "ai_custom_key": "", "ai_custom_model": "", "ai_custom_label": ""}
    assert _sent(seen, "surface", "/api/internal/ai-custom")["endpoint"] == ""


@pytest.mark.asyncio
async def test_a_provider_key_cleared_in_pilot_is_cleared_in_the_module(db, monkeypatch):
    db.add(AppSettings(key="ai_key_openai", value="sk-medsecure"))
    await db.commit()
    seen = _modules(monkeypatch)
    await settings._push_to_modules(db)
    keys = _sent(seen, "surface", "/api/ai/keys")
    assert {k: keys[k] for k in ("anthropic", "openai", "gemini", "bedrock", "ai_secret_bedrock")} == {
        "anthropic": "", "openai": "sk-medsecure", "gemini": "", "bedrock": "", "ai_secret_bedrock": ""}


@pytest.mark.asyncio
async def test_a_proxy_cleared_in_pilot_is_cleared_in_the_module(db, monkeypatch):
    seen = _modules(monkeypatch)
    await settings._push_to_modules(db)
    assert _sent(seen, "surface", "/api/internal/proxy") == {
        "http_proxy": "http://proxy.medsecure.example:3128", "https_proxy": "", "no_proxy": ""}


_UNREADABLE = "enc:v1:" + "QUJD" * 16  # well-formed marker, opens with no key


@pytest.mark.asyncio
async def test_provider_model_and_region_cleared_in_pilot_are_cleared_in_the_module(db, monkeypatch):
    seen = _modules(monkeypatch)
    await settings._push_to_modules(db)
    keys = _sent(seen, "surface", "/api/ai/keys")
    assert {k: keys[k] for k in ("provider", "model", "ai_region_bedrock")} == {
        "provider": "", "model": "", "ai_region_bedrock": ""}


@pytest.mark.asyncio
async def test_a_key_pilot_cannot_decrypt_is_not_sent_and_is_reported(db, monkeypatch):
    db.add(AppSettings(key="ai_key_openai", value=_UNREADABLE))
    await db.commit()
    seen = _modules(monkeypatch)
    report = await settings._push_to_modules(db)
    assert "openai" not in _sent(seen, "surface", "/api/ai/keys")
    assert _sent(seen, "surface", "/api/ai/keys")["anthropic"] == ""
    assert report == {m: "not sent, unreadable in Pilot (re-enter it): ai_key_openai"
                      for m in ("surface", "risk")}


@pytest.mark.asyncio
async def test_an_unreadable_custom_llm_key_leaves_the_modules_custom_llm_alone(db, monkeypatch):
    db.add(AppSettings(key="ai_custom_key", value=_UNREADABLE))
    await db.commit()
    seen = _modules(monkeypatch)
    report = await settings._push_to_modules(db)
    keys = _sent(seen, "surface", "/api/ai/keys")
    # Not the endpoint either: the module would pair the new one with its old key.
    assert not [k for k in keys if k.startswith("ai_custom_")]
    assert not [p for h, p, _ in seen if p == "/api/internal/ai-custom"]
    assert report["surface"] == "not sent, unreadable in Pilot (re-enter it): ai_custom_key"


@pytest.mark.asyncio
async def test_a_module_refusing_the_keys_still_receives_the_proxy(db, monkeypatch):
    seen = _modules(monkeypatch, refusing={("surface", "/api/ai/keys")})
    report = await settings._push_to_modules(db)
    assert report["surface"] == "ai_keys: HTTP 405"
    assert any(h == "surface" and p == "/api/internal/proxy" for h, p, _ in seen)


@pytest.mark.asyncio
async def test_an_error_mid_push_keeps_what_was_already_reported(db, monkeypatch):
    db.add(AppSettings(key="ai_key_openai", value=_UNREADABLE))
    await db.commit()
    _modules(monkeypatch)

    async def broken(*_a, **_k):
        raise httpx.ConnectError("connector registry unreachable")

    monkeypatch.setattr(settings, "_push_connectors_to", broken)
    report = await settings._push_to_modules(db)
    assert report["surface"] == ("not sent, unreadable in Pilot (re-enter it): ai_key_openai; "
                                 "error: connector registry unreachable")


async def _with_smtp(db, password=None):
    db.add_all([AppSettings(key="smtp_host", value="smtp.medsecure.example"),
                AppSettings(key="smtp_user", value="alerts@medsecure.example")])
    if password:
        db.add(AppSettings(key="smtp_password", value=password))
    await db.commit()


@pytest.mark.asyncio
async def test_an_smtp_password_pilot_cannot_decrypt_leaves_the_modules_smtp_alone(db, monkeypatch):
    await _with_smtp(db, _UNREADABLE)
    seen = _modules(monkeypatch)
    report = await settings._push_to_modules(db)
    assert not [p for _h, p, _b in seen if p == "/api/internal/smtp"]
    assert report["surface"] == "not sent, unreadable in Pilot (re-enter it): smtp_password"


@pytest.mark.asyncio
@pytest.mark.parametrize("absent", ["missing", "refusing"])
async def test_a_failed_smtp_push_is_reported_a_module_without_mail_is_not(db, monkeypatch, absent):
    await _with_smtp(db)
    _modules(monkeypatch, failing={("surface", "smtp")}, **{absent: {("risk", "smtp")}})
    report = await settings._push_to_modules(db)
    assert report == {"surface": "smtp: HTTP 500", "risk": "ok"}  # 404 / 405: no SMTP route


@pytest.mark.asyncio
async def test_a_stored_range_in_the_exceptions_is_left_out_and_reported(db, monkeypatch):
    db.add(AppSettings(key="no_proxy", value="localhost,10.0.0.0/8"))  # stored before ranges were refused
    await db.commit()
    seen = _modules(monkeypatch)
    report = await settings._push_to_modules(db)
    assert _sent(seen, "surface", "/api/internal/proxy")["no_proxy"] == "localhost"
    assert report["surface"] == "no_proxy: left out 10.0.0.0/8 (re-enter the exceptions)"


@pytest.mark.asyncio
async def test_the_custom_llm_key_pushed_is_the_one_stored(db, monkeypatch):
    await settings._set_setting("ai_custom_key", "sk-medsecure-llm", db)  # encrypted at rest
    await db.commit()
    seen = _modules(monkeypatch)
    await settings._push_to_modules(db)
    assert _sent(seen, "surface", "/api/ai/keys")["ai_custom_key"] == "sk-medsecure-llm"
    assert _sent(seen, "surface", "/api/internal/ai-custom")["key"] == "sk-medsecure-llm"



@pytest.mark.asyncio
async def test_a_key_cleared_through_the_settings_route_is_cleared_in_the_modules(db, monkeypatch):
    await settings._set_setting("ai_key_openai", "sk-medsecure", db)
    await db.commit()
    seen = _modules(monkeypatch)
    await settings.update_settings(settings.SettingsUpdate(ai_key_openai=""), user=None, db=db)
    assert _sent(seen, "surface", "/api/ai/keys")["openai"] == ""
