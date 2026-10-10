"""BUG-96 — Pilot's own outbound calls follow the proxy set in its settings.

Pilot pushed its proxy settings to every module but never applied them to
itself: its connectors (Microsoft Graph, Proofpoint, AWS through boto3), the
AI key validation and its other outbound calls went out directly, and failed
in a network where the proxy is the only way out. httpx and boto3 follow
HTTP(S)_PROXY / NO_PROXY from the process environment, so Pilot now exports
what its settings say, like the modules do. Locks, against SQLite:
  - after a save, the proxy is in Pilot's environment, its exceptions too;
  - every module Pilot calls with the service token is an exception (the
    hosts of its registry and of the default module URLs), so the push still
    reaches them directly while a public URL goes through the proxy;
  - a proxy cleared in the settings brings the deployment's own back;
  - a proxy on a private or metadata address is refused at save (400);
  - every save and every resync applies it;
  - start-up applies it before anything goes out; a database error leaves a
    readable NO_PROXY that still exempts the default module URLs and the
    backup agent, says so, and retries until the proxy is applied; any other
    error stops the start-up rather than leave Pilot on the wrong proxy;
  - a restored backup re-applies it, with the restored registry;
  - a registry host is an exception like any other: normalized, never "*",
    never a list; a stored exception httpx cannot read is left out, logged.
"""
import ast
import importlib
import json
import logging
import os
import socket
import sys
import urllib.request
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import proxy_common  # noqa: E402
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

_PROXY = "http://ops:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy")
_ADDRESSES = {"proxy.medsecure.example": "93.184.216.34", "proxy.internal.example": "10.0.0.8"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in _VARS:  # set then removed, so monkeypatch also undoes what Pilot exports
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var)
    for var in [v for v in os.environ if v.endswith("_URL") and v != "DATABASE_URL"]:
        monkeypatch.delenv(var)
    monkeypatch.setattr(proxy_common, "_ENV_PROXY", {"http_proxy": "", "https_proxy": ""})
    monkeypatch.setattr(proxy_common, "_ENV_NO_PROXY", "")
    monkeypatch.setattr(proxy_common, "_pushed", {"http_proxy": "", "https_proxy": ""})
    monkeypatch.setattr(proxy_common, "_pushed_no_proxy", "")
    monkeypatch.setattr(proxy_common, "_extra_internal", [], raising=False)
    monkeypatch.setattr(proxy_common, "_warned", set())  # each test sees its own warnings
    monkeypatch.setattr(settings, "_OWN_PROXY_RETRY_SECONDS", 0, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ADDRESSES.get(host, "93.184.216.34"), 0))])


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    f = async_sessionmaker(engine, expire_on_commit=False)
    async with f() as s:
        s.add_all([ModuleRegistry(id="surface", name="Surface", internal_url="http://surface-internal:8000",
                                  external_url="/surface/"),
                   ModuleRegistry(id="risk", name="Risk", internal_url="http://10.89.0.12:8080", external_url="/risk/")])
        await s.commit()
    yield f
    await engine.dispose()


@pytest_asyncio.fixture
async def db(factory):
    async with factory() as s:
        yield s


@pytest.fixture
def modules(monkeypatch):
    """The modules answer every push; anything else would be a proxied call."""
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(404 if request.url.path == "/api/connectors" else 200, json={"ok": True})

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}))
    return seen


def _direct(host: str) -> bool:
    """Whether httpx reaches this host directly on both schemes, from the
    environment Pilot set."""
    with httpx.Client() as c:
        return all(c._transport_for_url(httpx.URL(f"{scheme}://{host}/")) is c._transport
                   for scheme in ("http", "https"))


async def _save(db, **fields):
    return await settings.update_settings(settings.SettingsUpdate(**fields), user=None, db=db)


@pytest.mark.asyncio
async def test_a_saved_proxy_is_pilots_own(db, modules):
    await _save(db, https_proxy=_PROXY, http_proxy=_PROXY, no_proxy="ldap.medsecure.example")
    assert os.environ["HTTPS_PROXY"] == _PROXY and os.environ["HTTP_PROXY"] == _PROXY
    assert urllib.request.proxy_bypass_environment("ldap.medsecure.example")
    assert not urllib.request.proxy_bypass_environment("api.openai.com")


@pytest.mark.asyncio
async def test_every_module_pilot_calls_is_reached_directly(db, modules):
    resp = await _save(db, https_proxy=_PROXY, http_proxy=_PROXY)
    for host in ("surface-internal", "10.89.0.12", "watch-app", "localhost", "127.0.0.1"):
        assert _direct(host), host
    assert not _direct("graph.microsoft.com")  # a public URL does go through the proxy
    assert set(resp["push"].values()) == {"ok"}
    assert sorted(set(modules)) == ["10.89.0.12", "surface-internal"]


@pytest.mark.asyncio
async def test_a_proxy_cleared_in_the_settings_brings_the_deployments_back(db, modules, monkeypatch):
    corp = "http://corp-proxy.medsecure.example:3128"
    monkeypatch.setattr(proxy_common, "_ENV_PROXY", {"http_proxy": "", "https_proxy": corp})
    await _save(db, https_proxy=_PROXY)
    assert os.environ["HTTPS_PROXY"] == _PROXY
    await _save(db, https_proxy="")
    assert os.environ["HTTPS_PROXY"] == corp


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["http_proxy", "https_proxy"])
@pytest.mark.parametrize("url", ["http://proxy.internal.example:3128", "http://169.254.169.254"])
async def test_a_proxy_on_an_internal_address_is_refused_at_save(db, modules, field, url):
    with pytest.raises(HTTPException) as exc:
        await _save(db, **{field: url})
    assert exc.value.status_code == 400
    assert (await db.execute(select(AppSettings).where(AppSettings.key == field))).scalar_one_or_none() is None
    assert field.upper() not in os.environ
    assert modules == []


@pytest.mark.asyncio
async def test_a_resync_applies_it(db, modules):
    db.add(AppSettings(key="https_proxy", value=_PROXY))
    await db.commit()
    resp = await settings.resync_modules(user=None, db=db)
    assert os.environ["HTTPS_PROXY"] == _PROXY
    assert _direct("surface-internal") and not _direct("graph.microsoft.com")
    assert set(resp["push"].values()) == {"ok"}


@pytest.mark.asyncio
async def test_a_registry_host_is_never_star_nor_a_list(factory, modules, caplog):
    async with factory() as s:
        s.add_all([ModuleRegistry(id="asset", name="Asset", internal_url="http://*:8080", external_url="/asset/"),
                   ModuleRegistry(id="audit", name="Audit", internal_url="http://graph.microsoft.com,audit-app/",
                                  external_url="/audit/")])
        await s.commit()
        with caplog.at_level(logging.WARNING):
            await _save(s, https_proxy=_PROXY, http_proxy=_PROXY)
    entries = os.environ["NO_PROXY"].split(",")
    assert "*" not in entries and "graph.microsoft.com" not in entries
    assert not _direct("graph.microsoft.com") and _direct("surface-internal")


@pytest.mark.asyncio
async def test_a_stored_exception_httpx_cannot_read_is_left_out_and_logged(factory, caplog):
    async with factory() as s:
        s.add_all([AppSettings(key="https_proxy", value=_PROXY),
                   AppSettings(key="no_proxy", value="ldap.medsecure.example,10.0.0.0/8")])
        await s.commit()
    with caplog.at_level(logging.WARNING):
        await settings.restore_own_proxy(factory)
    assert "10.0.0.0/8" not in os.environ["NO_PROXY"] and _direct("ldap.medsecure.example")
    assert [r for r in caplog.records if "10.0.0.0/8" in r.getMessage()]


@pytest.mark.asyncio
async def test_start_up_applies_it(factory, modules):
    async with factory() as s:
        s.add(AppSettings(key="https_proxy", value=_PROXY))
        await s.commit()
    await settings.restore_own_proxy(factory)
    assert os.environ["HTTPS_PROXY"] == _PROXY
    assert urllib.request.proxy_bypass_environment("surface-internal")


def _database_down():
    raise OperationalError("SELECT", {}, ConnectionRefusedError("database not ready"))


@pytest.mark.asyncio
async def test_a_database_not_ready_at_start_up_leaves_a_readable_no_proxy(monkeypatch, caplog):
    monkeypatch.setattr(proxy_common, "_ENV_NO_PROXY", "fd00::/8,localhost")
    with caplog.at_level(logging.WARNING, logger="pilot.settings"):
        retry = await settings.restore_own_proxy(_database_down)
    retry.cancel()
    assert [r for r in caplog.records if r.name == "pilot.settings" and "own proxy not applied" in r.getMessage()]
    assert os.environ.get("NO_PROXY") == "localhost"
    httpx.Client().close()


@pytest.mark.asyncio
async def test_a_database_not_ready_still_exempts_the_default_modules(monkeypatch):
    monkeypatch.setattr(proxy_common, "_ENV_PROXY", {"http_proxy": _PROXY, "https_proxy": _PROXY})
    retry = await settings.restore_own_proxy(_database_down)
    retry.cancel()
    assert os.environ["HTTPS_PROXY"] == _PROXY
    assert _direct("watch-app") and _direct("risk-app") and _direct("backup-agent")
    assert not _direct("graph.microsoft.com")


@pytest.mark.asyncio
async def test_a_database_not_ready_is_retried_until_the_proxy_applies(factory, modules):
    async with factory() as s:
        s.add(AppSettings(key="https_proxy", value=_PROXY))
        await s.commit()
    calls = []

    def flaky():
        calls.append(1)
        return _database_down() if len(calls) < 3 else factory()

    retry = await settings.restore_own_proxy(flaky)
    assert "HTTPS_PROXY" not in os.environ
    await retry
    assert len(calls) == 3 and os.environ["HTTPS_PROXY"] == _PROXY and _direct("surface-internal")


class _RefusingSession:
    """A session whose first query hits a database that refuses the
    connection: asyncpg raises the bare OSError."""
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, *a, **k):
        raise ConnectionRefusedError(111, "Connect call failed ('10.89.0.5', 5432)")


@pytest.mark.asyncio
async def test_a_refused_connection_at_start_up_is_retried(factory, modules, caplog):
    async with factory() as s:
        s.add(AppSettings(key="https_proxy", value=_PROXY))
        await s.commit()
    calls = []

    def refusing_then_up():
        calls.append(1)
        return _RefusingSession() if len(calls) < 2 else factory()

    with caplog.at_level(logging.WARNING, logger="pilot.settings"):
        retry = await settings.restore_own_proxy(refusing_then_up)
    assert [r for r in caplog.records if "own proxy not applied" in r.getMessage()]
    await retry
    assert os.environ["HTTPS_PROXY"] == _PROXY


@pytest.mark.asyncio
async def test_a_bug_met_while_retrying_is_logged_as_an_error(caplog):
    calls = []

    def down_then_broken():
        calls.append(1)
        if len(calls) < 2:
            return _database_down()
        raise AttributeError("a bug in the retry")

    with caplog.at_level(logging.WARNING, logger="pilot.settings"):
        retry = await settings.restore_own_proxy(down_then_broken)
        await retry
    assert [r for r in caplog.records if r.levelno == logging.ERROR and "own proxy" in r.getMessage()]


@pytest.mark.asyncio
async def test_any_other_error_at_start_up_is_not_swallowed():
    def broken():
        raise AttributeError("a bug, not a database not ready")

    with pytest.raises(AttributeError):
        await settings.restore_own_proxy(broken)


def test_on_startup_awaits_it():
    tree = ast.parse((Path(__file__).resolve().parents[2] / "src" / "main.py").read_text(encoding="utf-8"))
    [startup] = [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "on_startup"]
    # Called at the top level of on_startup (not under a condition), before
    # the seed and the schedulers, which already go out.
    def name(call):
        return getattr(call.func, "attr", getattr(call.func, "id", ""))

    [restore] = [n.lineno for n in startup.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Await)
                 and isinstance(n.value.value, ast.Call) and name(n.value.value) == "restore_own_proxy"]
    later = [c.lineno for c in ast.walk(startup) if isinstance(c, ast.Call)
             and (name(c) == "seed_kpi_catalog" or name(c).startswith("start_"))]
    assert later and restore < min(later)


@pytest.mark.asyncio
async def test_a_restored_backup_re_applies_it(db, modules):
    from src.routes import backups
    await backups._pilot_self_restore(db, {
        "module_registry": [{"id": "asset", "name": "Asset", "internal_url": "http://asset-restored:8080",
                             "external_url": "/asset/"}],
        "app_settings": [{"key": "https_proxy", "value": _PROXY}, {"key": "http_proxy", "value": _PROXY}],
    })
    assert os.environ["HTTPS_PROXY"] == _PROXY
    assert _direct("asset-restored") and not _direct("graph.microsoft.com")


@pytest.mark.asyncio
@pytest.mark.parametrize("restored", [
    {"https_proxy": "http://169.254.169.254"},                                   # metadata
    {"https_proxy": "http://proxy.internal.example:3128"},                       # resolves to 10.0.0.8
    {"https_proxy": "http://1.1.1.1:3128/,http://127.0.0.1:8080"},               # a list
    {"no_proxy": "10.0.0.0/8"},                                                  # a range
])
async def test_a_restored_proxy_is_validated_like_a_saved_one(db, modules, caplog, restored):
    """A backup comes from anywhere: the proxy it carries goes through the
    checks of a save. One refused leaves the current value in place, logged."""
    from src.routes import backups
    db.add_all([AppSettings(key="https_proxy", value=_PROXY), AppSettings(key="no_proxy", value="ldap.medsecure.example")])
    await db.commit()
    with caplog.at_level(logging.WARNING):
        result = await backups._pilot_self_restore(db, {
            "app_settings": [{"key": k, "value": v} for k, v in restored.items()]})
    [(key, _value)] = restored.items()
    assert result["left_out"] == [key]
    assert await settings._get_setting("https_proxy", db) == _PROXY
    assert await settings._get_setting("no_proxy", db) == "ldap.medsecure.example"
    assert os.environ["HTTPS_PROXY"] == _PROXY
    assert [r for r in caplog.records if key in r.getMessage()]


@pytest.mark.asyncio
async def test_the_restore_route_says_which_proxy_setting_it_left_out(db, modules):
    from src.routes import backups
    db.add(AppSettings(key="backup_pilot_20261010_120000", value=json.dumps({"module": "pilot", "data": [
        {"data": {"app_settings": [{"key": "https_proxy", "value": "http://169.254.169.254"}]}}]})))
    await db.commit()
    answer = await backups.restore_backup("backup_pilot_20261010_120000", user=None, db=db)
    assert answer["left_out"] == ["https_proxy"]
