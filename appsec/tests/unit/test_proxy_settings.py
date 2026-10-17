"""FEAT-58 — the outbound proxy is settable in the module itself when Pilot is absent.

The shared router (``src/proxy_settings_common.py``), mounted as the modules
mount it, against SQLite. Only the test host names are faked in the resolver.
Locks:
  - standalone: an admin PUT writes the ``proxy.*`` rows (encrypted at rest)
    and exports the proxy into the process environment at once;
  - an empty field removes its row and hands the field back to the
    deployment's own proxy;
  - an on-site proxy on a private address is accepted; loopback, link-local
    (metadata), the suite's own services, a non-http scheme, a list of URLs
    and an exception range are refused, and nothing is stored;
  - GET never returns the password of a proxy URL; sending the masked URL
    back keeps the stored password, a masked URL that changed is refused;
  - GET reports the deployment's own proxy, which applies when nothing is
    saved;
  - suite (``AUTH_MODE=pilot``): PUT is refused with 409, GET says managed;
  - a non-admin cannot write; with authentication disabled the caller is the
    admin;
  - the Pilot push keeps refusing a private proxy.
"""
from __future__ import annotations

import os
import socket
import sys
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/appsec_test")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import proxy_common, proxy_settings_common  # noqa: E402
from src.auth import get_current_user  # noqa: E402
from src.database import get_db  # noqa: E402
from src.models import AppSettings  # noqa: E402
from src.settings_crypto import decrypt_setting, is_encrypted  # noqa: E402

_PROXY_ENV = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")
_FAKE_DNS = {"proxy.medsecure.example": "93.184.216.34", "squid.medsecure.example": "10.0.0.8",
             "other.medsecure.example": "93.184.216.35"}
_real_getaddrinfo = socket.getaddrinfo


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Resolve the test names; leave every other lookup to the real resolver."""
    def getaddrinfo(host, *args, **kwargs):
        if host in _FAKE_DNS:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_FAKE_DNS[host], 0))]
        return _real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


@pytest.fixture(autouse=True)
def clean_proxy(monkeypatch):
    """No proxy in the environment nor in proxy_common's state, before and after."""
    for var in _PROXY_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(proxy_common, "_pushed", {"http_proxy": "", "https_proxy": ""})
    monkeypatch.setattr(proxy_common, "_pushed_no_proxy", "")
    monkeypatch.setitem(proxy_common._ENV_PROXY, "http_proxy", "")
    monkeypatch.setitem(proxy_common._ENV_PROXY, "https_proxy", "")


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

    def _make(mode: str = "standalone", role: str | None = "admin"):
        monkeypatch.setattr(proxy_settings_common, "AUTH_MODE", mode)
        app = FastAPI()
        app.include_router(proxy_settings_common.router)
        app.dependency_overrides[get_db] = _db
        app.dependency_overrides[get_current_user] = (
            (lambda: None) if role is None else (lambda: SimpleNamespace(_module_role=role)))
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")

    return _make, sessions


async def _rows(sessions) -> dict[str, str]:
    async with sessions() as s:
        rows = (await s.execute(select(AppSettings).where(AppSettings.key.like("proxy.%")))).scalars()
        return {r.key: r.value for r in rows}


_WITH_CREDS = "http://ops:s3cret@proxy.medsecure.example:3128"


@pytest.mark.asyncio
async def test_standalone_put_stores_encrypted_and_exports(make_client):
    make, sessions = make_client
    async with make() as c:
        r = await c.put("/api/proxy/config", json={
            "http_proxy": _WITH_CREDS, "https_proxy": "http://proxy.medsecure.example:3128",
            "no_proxy": "intranet.medsecure.example"})
    assert r.status_code == 200, r.text
    rows = await _rows(sessions)
    assert all(is_encrypted(v) for v in rows.values())  # at rest
    assert decrypt_setting(rows["proxy.http_proxy"]) == _WITH_CREDS
    assert os.environ["HTTP_PROXY"] == _WITH_CREDS
    assert os.environ["HTTPS_PROXY"] == "http://proxy.medsecure.example:3128"
    assert "intranet.medsecure.example" in os.environ["NO_PROXY"].split(",")


@pytest.mark.asyncio
async def test_empty_field_hands_back_to_the_deployment_proxy(make_client, monkeypatch):
    make, sessions = make_client
    monkeypatch.setitem(proxy_common._ENV_PROXY, "https_proxy", "http://env-proxy.example:8080")
    async with make() as c:
        await c.put("/api/proxy/config", json={"https_proxy": "http://proxy.medsecure.example:3128"})
        assert os.environ["HTTPS_PROXY"] == "http://proxy.medsecure.example:3128"
        r = await c.put("/api/proxy/config", json={"https_proxy": ""})
    assert r.status_code == 200
    assert await _rows(sessions) == {}
    assert os.environ["HTTPS_PROXY"] == "http://env-proxy.example:8080"


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://squid.medsecure.example:3128", "http://10.0.0.8:3128",
                                 "http://192.168.1.10:8080"])
async def test_on_site_private_proxy_is_accepted(make_client, url):
    make, _ = make_client
    async with make() as c:
        r = await c.put("/api/proxy/config", json={"https_proxy": url})
    assert r.status_code == 200, r.text
    assert os.environ["HTTPS_PROXY"] == url


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"https_proxy": "http://127.0.0.1:3128"},
    {"https_proxy": "http://localhost:3128"},
    {"https_proxy": "http://169.254.169.254"},
    {"https_proxy": "http://[::1]:3128"},
    {"https_proxy": "http://pilot-app:8000"},
    {"https_proxy": "socks5://proxy.medsecure.example:1080"},
    {"https_proxy": "file:///etc/passwd"},
    {"https_proxy": "http://proxy.medsecure.example:3128,http://10.0.0.8:3128"},
    {"https_proxy": "http://proxy.medsecure.example:3128", "no_proxy": "10.0.0.0/8"},
])
async def test_unsafe_proxy_or_exception_is_refused_and_nothing_stored(make_client, body):
    make, sessions = make_client
    async with make() as c:
        r = await c.put("/api/proxy/config", json=body)
    assert r.status_code == 400, r.text
    assert await _rows(sessions) == {}
    assert "HTTPS_PROXY" not in os.environ


@pytest.mark.asyncio
async def test_get_never_returns_the_password(make_client):
    make, _ = make_client
    async with make() as c:
        await c.put("/api/proxy/config", json={"http_proxy": _WITH_CREDS})
        r = await c.get("/api/proxy/config")
    assert "s3cret" not in r.text
    assert r.json()["http_proxy"] == f"http://ops:{proxy_settings_common.MASK}@proxy.medsecure.example:3128"
    assert r.json()["managed"] is False


@pytest.mark.asyncio
async def test_masked_url_sent_back_keeps_the_stored_password(make_client):
    make, sessions = make_client
    async with make() as c:
        await c.put("/api/proxy/config", json={"http_proxy": _WITH_CREDS})
        masked = (await c.get("/api/proxy/config")).json()["http_proxy"]
        r = await c.put("/api/proxy/config", json={"http_proxy": masked, "no_proxy": "intranet.medsecure.example"})
    assert r.status_code == 200, r.text
    assert decrypt_setting((await _rows(sessions))["proxy.http_proxy"]) == _WITH_CREDS
    assert os.environ["HTTP_PROXY"] == _WITH_CREDS


@pytest.mark.asyncio
async def test_masked_url_that_changed_is_refused(make_client):
    make, sessions = make_client
    async with make() as c:
        await c.put("/api/proxy/config", json={"http_proxy": _WITH_CREDS})
        r = await c.put("/api/proxy/config", json={
            "http_proxy": f"http://ops:{proxy_settings_common.MASK}@other.medsecure.example:3128"})
    assert r.status_code == 400
    assert decrypt_setting((await _rows(sessions))["proxy.http_proxy"]) == _WITH_CREDS


@pytest.mark.asyncio
async def test_get_reports_the_deployment_proxy(make_client, monkeypatch):
    make, _ = make_client
    monkeypatch.setitem(proxy_common._ENV_PROXY, "https_proxy", "http://ops:envpass@env-proxy.example:8080")
    async with make() as c:
        r = await c.get("/api/proxy/config")
    assert r.json()["https_proxy"] == ""
    assert r.json()["env"]["https_proxy"] == f"http://ops:{proxy_settings_common.MASK}@env-proxy.example:8080"
    assert "envpass" not in r.text


@pytest.mark.asyncio
async def test_suite_mode_refuses_writes(make_client):
    make, sessions = make_client
    async with make(mode="pilot") as c:
        r = await c.put("/api/proxy/config", json={"https_proxy": "http://proxy.medsecure.example:3128"})
        g = await c.get("/api/proxy/config")
    assert r.status_code == 409
    assert g.json()["managed"] is True
    assert await _rows(sessions) == {}


@pytest.mark.asyncio
async def test_non_admin_cannot_write(make_client):
    make, sessions = make_client
    async with make(role="viewer") as c:
        r = await c.put("/api/proxy/config", json={"https_proxy": "http://proxy.medsecure.example:3128"})
    assert r.status_code == 403
    assert await _rows(sessions) == {}


@pytest.mark.asyncio
async def test_auth_disabled_caller_is_the_admin(make_client):
    make, _ = make_client
    async with make(role=None) as c:
        r = await c.put("/api/proxy/config", json={"https_proxy": "http://proxy.medsecure.example:3128"})
    assert r.status_code == 200, r.text


def test_pilot_push_still_refuses_a_private_proxy():
    from src.routes.internal import _validate_proxy_url
    with pytest.raises(HTTPException) as exc:
        _validate_proxy_url("http://squid.medsecure.example:3128")
    assert exc.value.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("url, secret", [
    ("http://TOKEN123@proxy.medsecure.example:3128", "TOKEN123"),      # a token as the user name
    ("http://ops%3As3cret@proxy.medsecure.example:3128", "s3cret"),    # httpx reads ops:s3cret
    ("http://op%40s:s3cret@proxy.medsecure.example:3128", "s3cret"),
    ("http://TOKEN123:@proxy.medsecure.example:3128", "TOKEN123"),      # a token, empty password
    ("http://op%3Ax:s3cret@proxy.medsecure.example:3128", "op%3Ax"),   # httpx reads user op:x
])
async def test_get_never_returns_any_credential(make_client, url, secret):
    make, sessions = make_client
    async with make() as c:
        assert (await c.put("/api/proxy/config", json={"https_proxy": url})).status_code == 200
        r = await c.get("/api/proxy/config")
        assert secret not in r.text
        masked = r.json()["https_proxy"]
        assert proxy_settings_common.MASK in masked
        # Sent back unchanged, it keeps the stored credentials.
        assert (await c.put("/api/proxy/config", json={"https_proxy": masked})).status_code == 200
    assert decrypt_setting((await _rows(sessions))["proxy.https_proxy"]) == url


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://ops:Zq9/xw@proxy.medsecure.example:3128",   # an unencoded / splits the URL early
    "http://ops:Zq9?xw@127.0.0.1:3128",
    "http://ops:Zq9#xw@127.0.0.1:3128",
    "http://ops:Zq9xw@127.0.0.1:3128",
    "http://ZQ9TOKEN/x@127.0.0.1:3128",   # the resolver's error quotes the host in lower case
    "http://Zq9Token/@proxy.medsecure.example:3128",
])
async def test_a_refusal_never_echoes_the_credentials(make_client, url):
    make, _ = make_client
    async with make() as c:
        r = await c.put("/api/proxy/config", json={"https_proxy": url})
    assert r.status_code == 400
    assert "zq9" not in r.text.lower() and "ops" not in r.text


@pytest.mark.asyncio
async def test_a_partial_put_leaves_the_other_fields(make_client):
    make, sessions = make_client
    async with make() as c:
        await c.put("/api/proxy/config", json={
            "http_proxy": "http://proxy.medsecure.example:3128", "no_proxy": "intranet.medsecure.example"})
        r = await c.put("/api/proxy/config", json={"https_proxy": "http://squid.medsecure.example:3128"})
    assert r.status_code == 200
    assert set(await _rows(sessions)) == {"proxy.http_proxy", "proxy.https_proxy", "proxy.no_proxy"}
