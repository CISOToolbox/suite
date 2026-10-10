"""BUG-95 — what Pilot checks an AI key with: the proxy being saved, and the
right key for the right endpoint.

A key and a new proxy saved together were checked before the proxy applied
(with the old one, or directly): on a network where only the proxy goes out,
the save was refused as "invalid key". And the custom LLM was checked with
the stored key against whatever endpoint had just been typed. Locks, through
``update_settings`` against SQLite, the outgoing client recorded:
  - the check goes through the proxy of the body, else the stored one, else
    the deployment's own; a host in the exceptions is reached directly;
  - a proxy refused at save is never used for a check;
  - a new custom endpoint needs the key typed again; the stored key only
    goes to the endpoint it was saved with;
  - clearing the key of an LLM that requires one says to clear the endpoint.
"""
import json
import os
import socket
import sys

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
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.models import AppSettings, Base  # noqa: E402
from src.routes import settings  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb", "false", "true")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()


@pytest.fixture(autouse=True)
def _no_proxy_left_behind(monkeypatch):
    """The push applies Pilot's own proxy to the process: undo it after each test."""
    from src import proxy_common
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var)
    monkeypatch.setattr(proxy_common, "_ENV_PROXY", {"http_proxy": "", "https_proxy": ""})
    monkeypatch.setattr(proxy_common, "_ENV_NO_PROXY", "")
    monkeypatch.setattr(proxy_common, "_pushed", {"http_proxy": "", "https_proxy": ""})
    monkeypatch.setattr(proxy_common, "_pushed_no_proxy", "")
    monkeypatch.setattr(proxy_common, "_extra_internal", [])


    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ADDRESSES.get(host, "93.184.216.34"), 0))])


_PROXY = "http://ops:s3cret@proxy.medsecure.example:3128"
_CORP = "http://corp-proxy.medsecure.example:3128"
_ADDRESSES = {"proxy.internal.example": "10.0.0.8"}
_ENDPOINT = "https://llm.medsecure.example/v1"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def checks(monkeypatch):
    """Every transport Pilot opens, with its proxy, and every request sent
    through it. ``checks.status`` is what the provider answers; a request
    through a client without its own transport is kept under ``unrouted``."""
    class Seen(list):
        status = 200
        unrouted: list = []

        def posts(self):
            return [(proxy, str(req.url), req.headers) for proxy, sent in self for req in sent]

    seen = Seen()
    seen.unrouted = []

    def transport(*_a, proxy=None, **_k):
        sent = []
        seen.append((proxy, sent))
        return httpx.MockTransport(lambda req: (sent.append(req), httpx.Response(seen.status, json={}))[1])

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: real_client(*a, **{
        **k, "transport": k.get("transport") or httpx.MockTransport(
            lambda req: (seen.unrouted.append(req), httpx.Response(599))[1])}))
    return seen


def _proxy_of(checks) -> str | None:
    """The proxy the one key check went through; None: directly."""
    [(proxy, _url, _headers)] = checks.posts()
    assert checks.unrouted == []  # never a client left to the environment of the moment
    return proxy


async def _save(db, **fields):
    return await settings.update_settings(settings.SettingsUpdate(**fields), user=None, db=db)


async def _stored(db, key):
    row = (await db.execute(select(AppSettings).where(AppSettings.key == key))).scalar_one_or_none()
    return row.value if row else None


@pytest.mark.asyncio
async def test_a_key_saved_with_a_new_proxy_is_checked_through_it(db, checks):
    await _save(db, ai_key_openai="sk-medsecure", https_proxy=_PROXY, http_proxy=_PROXY)
    assert _proxy_of(checks) == _PROXY


@pytest.mark.asyncio
async def test_a_key_saved_alone_is_checked_through_the_stored_proxy(db, checks):
    await settings._set_setting("https_proxy", _PROXY, db)
    await db.commit()
    await _save(db, ai_key_openai="sk-medsecure")
    assert _proxy_of(checks) == _PROXY


@pytest.mark.asyncio
async def test_a_proxy_cleared_with_the_key_brings_the_deployments_back(db, checks, monkeypatch):
    from src import proxy_common
    monkeypatch.setattr(proxy_common, "_ENV_PROXY", {"http_proxy": "", "https_proxy": _CORP})
    await settings._set_setting("https_proxy", _PROXY, db)
    await db.commit()
    await _save(db, ai_key_anthropic="sk-ant-medsecure", https_proxy="")
    assert _proxy_of(checks) == _CORP


@pytest.mark.asyncio
@pytest.mark.parametrize("exceptions", ["api.openai.com", "openai.com", "*.openai.com"])
async def test_a_host_in_the_exceptions_is_checked_directly(db, checks, exceptions):
    await _save(db, ai_key_openai="sk-medsecure", https_proxy=_PROXY, no_proxy=exceptions)
    assert _proxy_of(checks) is None


@pytest.mark.asyncio
async def test_an_exception_with_a_port_covers_that_port_only(db, checks):
    """As httpx reads it, which every later call of Pilot follows: the URL of
    the check names no port, so the exception does not cover it."""
    await _save(db, ai_key_openai="sk-medsecure", https_proxy=_PROXY, no_proxy="api.openai.com:443")
    assert _proxy_of(checks) == _PROXY


@pytest.mark.asyncio
async def test_a_deployment_exception_is_honoured(db, checks, monkeypatch):
    from src import proxy_common
    monkeypatch.setattr(proxy_common, "_ENV_NO_PROXY", "generativelanguage.googleapis.com")
    await _save(db, ai_key_gemini="gm-medsecure", https_proxy=_PROXY)
    assert _proxy_of(checks) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("proxy", ["http://proxy.internal.example:3128", "http://169.254.169.254"])
async def test_a_refused_proxy_is_never_used_for_a_check(db, checks, proxy):
    with pytest.raises(HTTPException) as exc:
        await _save(db, ai_key_openai="sk-medsecure", https_proxy=proxy)
    assert exc.value.status_code == 400
    assert checks.posts() == []


async def _custom_llm(db, endpoint=_ENDPOINT, key="sk-medsecure-llm"):
    await settings._set_setting("ai_custom_endpoint", endpoint, db)
    await settings._set_setting("ai_custom_model", "medsecure-llm", db)
    await settings._set_setting("ai_custom_key", key, db)
    await db.commit()


def _keys_sent(checks):
    return [headers.get("Authorization") for _proxy, _url, headers in checks.posts()]


@pytest.mark.asyncio
async def test_a_new_endpoint_needs_the_key_again(db, checks):
    await _custom_llm(db)
    with pytest.raises(HTTPException) as exc:
        await _save(db, ai_custom_endpoint="https://llm.elsewhere.example/v1", ai_custom_model="medsecure-llm")
    assert exc.value.status_code == 400 and "needs its API key typed again" in exc.value.detail
    assert checks.posts() == []  # the stored key went nowhere
    assert await _stored(db, "ai_custom_endpoint") == _ENDPOINT


@pytest.mark.asyncio
async def test_a_new_endpoint_with_its_key_is_checked_with_that_key(db, checks):
    await _custom_llm(db)
    await _save(db, ai_custom_endpoint="https://llm.elsewhere.example/v1", ai_custom_model="medsecure-llm",
                ai_custom_key="sk-elsewhere")
    assert _keys_sent(checks) == ["Bearer sk-elsewhere"]


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [_ENDPOINT, _ENDPOINT + "/"])
async def test_the_same_endpoint_is_checked_with_the_stored_key(db, checks, endpoint):
    await _custom_llm(db)
    await _save(db, ai_custom_endpoint=endpoint, ai_custom_model="other-model")
    assert _keys_sent(checks) == ["Bearer sk-medsecure-llm"]


@pytest.mark.asyncio
async def test_a_first_endpoint_does_not_take_a_key_stored_without_one(db, checks):
    await settings._set_setting("ai_custom_key", "sk-medsecure-llm", db)
    await db.commit()
    with pytest.raises(HTTPException) as exc:
        await _save(db, ai_custom_endpoint=_ENDPOINT, ai_custom_model="medsecure-llm")
    assert exc.value.status_code == 400 and "needs its API key typed again" in exc.value.detail
    assert checks.posts() == []


@pytest.mark.asyncio
async def test_clearing_a_required_key_says_to_clear_the_endpoint(db, checks):
    await _custom_llm(db)
    checks.status = 401
    with pytest.raises(HTTPException) as exc:
        await _save(db, ai_custom_endpoint=_ENDPOINT, ai_custom_model="medsecure-llm", ai_custom_key="")
    assert exc.value.status_code == 400 and "clear the endpoint as well" in exc.value.detail
    assert _keys_sent(checks) == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("resolves", [False, True])  # no public DNS for Pilot, or a public answer
async def test_the_custom_llm_is_checked_by_name_through_the_proxy(db, checks, monkeypatch, resolves):
    if not resolves:  # Pilot resolves its proxy, not the public names behind it
        resolve = socket.getaddrinfo

        def no_public_dns(host, *a, **k):
            if host == "llm.medsecure.example":
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            return resolve(host, *a, **k)
        monkeypatch.setattr(socket, "getaddrinfo", no_public_dns)
    await _save(db, ai_custom_endpoint=_ENDPOINT, ai_custom_model="medsecure-llm", ai_custom_key="sk-medsecure-llm",
                https_proxy=_PROXY)
    [(proxy, url, headers)] = checks.posts()
    assert (proxy, url) == (_PROXY, _ENDPOINT + "/chat/completions")
    assert headers["Authorization"] == "Bearer sk-medsecure-llm"


@pytest.mark.asyncio
async def test_the_custom_llm_checked_directly_stays_pinned(db, checks):
    await _save(db, ai_custom_endpoint=_ENDPOINT, ai_custom_model="medsecure-llm", ai_custom_key="sk-medsecure-llm")
    [(proxy, url, headers)] = checks.posts()
    assert (proxy, url) == (None, "https://93.184.216.34/v1/chat/completions")
    assert headers["Host"] == "llm.medsecure.example"


@pytest.mark.asyncio
async def test_through_the_proxy_a_custom_llm_resolving_to_a_private_address_is_refused(db, checks):
    _ADDRESSES["llm.medsecure.example"] = "10.0.0.5"
    try:
        with pytest.raises(HTTPException) as exc:
            await _save(db, ai_custom_endpoint=_ENDPOINT, ai_custom_model="medsecure-llm",
                        ai_custom_key="sk-medsecure-llm", https_proxy=_PROXY)
    finally:
        del _ADDRESSES["llm.medsecure.example"]
    assert exc.value.status_code == 400
    assert checks.posts() == [] and checks.unrouted == []


@pytest.mark.asyncio
async def test_a_new_endpoint_alone_needs_the_key_again(db, checks):
    """The body names the endpoint only (no model): the guard applies all the same."""
    await _custom_llm(db)
    with pytest.raises(HTTPException) as exc:
        await _save(db, ai_custom_endpoint="https://llm.elsewhere.example/v1")
    assert exc.value.status_code == 400 and "needs its API key typed again" in exc.value.detail
    assert checks.posts() == []
    assert await _stored(db, "ai_custom_endpoint") == _ENDPOINT


@pytest.mark.asyncio
async def test_the_same_endpoint_alone_is_checked_with_the_stored_model(db, checks):
    await _custom_llm(db)
    await _save(db, ai_custom_endpoint=_ENDPOINT)
    [(_proxy, _url, _headers)] = checks.posts()
    [req] = [r for _p, sent in checks for r in sent]
    assert json.loads(req.content)["model"] == "medsecure-llm"
