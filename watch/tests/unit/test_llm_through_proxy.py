"""BUG-95 — Watch's AI calls reach a custom LLM through the outbound proxy.

Watch has its own two calls to the custom LLM (``call_llm_text`` for the
server-side analysis, ``POST /api/ai/complete``, the assistant), which now share one post. The
route also answered 503 for ``custom``: it asked for an ``ai_key_custom``
and a catalogue entry the custom LLM never has. Both resolved the endpoint
locally and connected to the pinned IP: behind a proxy, a network without
public DNS never reached it, and the proxy was asked to ``CONNECT`` an IP.
Locks, against SQLite with the network replaced: through the proxy the
request names the endpoint, even unresolvable here; a name resolving to a
private address is still refused; without a proxy it stays pinned.
"""
from __future__ import annotations

import os
import socket
import sys

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/watch_test")
os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.models import AppSettings  # noqa: E402
from src.routes import ai  # noqa: E402
from src.schemas import AICompleteRequest  # noqa: E402

_HOST = "llm.medsecure.example"
_PROXY = "http://ops:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    import src.routes.internal as internal
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(internal, "_custom_llm", {})  # the stored config is the one read


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add_all([AppSettings(key="ai_custom_endpoint", value=f"https://{_HOST}/v1"),
                         AppSettings(key="ai_custom_model", value="medsecure-llm"),
                         AppSettings(key="ai_custom_key", value="sk-medsecure-llm")])
        await session.commit()
        yield session
    await engine.dispose()


@pytest.fixture
def network(monkeypatch):
    """DNS answers ``resolves_to`` (None: no DNS); transports and requests are
    recorded; a request through a client without its own transport is kept
    under ``unrouted``, off the real network."""
    state = {"resolves_to": "93.184.216.34", "proxies": [], "requests": [], "unrouted": []}

    def getaddrinfo(host, *a, **k):
        if state["resolves_to"] is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (state["resolves_to"], 0))]

    def reply(request):
        state["requests"].append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "brief: patch now"}}]})

    def transport(*_a, proxy=None, **_k):
        state["proxies"].append(proxy)
        return httpx.MockTransport(reply)

    def unrouted(request):
        state["unrouted"].append(request)
        return httpx.Response(599)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: real_client(
        *a, **{**k, "transport": k.get("transport") or httpx.MockTransport(unrouted)}))
    return state


async def _text(db):
    return await ai.call_llm_text(db, "system", "a CVE", provider="custom", model="medsecure-llm")


async def _complete(db):
    resp = await ai.ai_complete(AICompleteRequest(system="system", user="a CVE", provider="custom",
                                                  model="medsecure-llm"), user=None, db=db)
    return resp["text"] if isinstance(resp, dict) else resp.text


_CALLS = [_text, _complete]


@pytest.mark.asyncio
@pytest.mark.parametrize("call", _CALLS)
async def test_the_custom_llm_is_reached_by_name_through_the_proxy(db, network, monkeypatch, call):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    network["resolves_to"] = None  # no public DNS here: only the proxy resolves
    assert await call(db) == "brief: patch now"
    [req] = network["requests"]
    assert str(req.url) == f"https://{_HOST}/v1/chat/completions"
    assert network["proxies"] == [_PROXY] and network["unrouted"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("call", _CALLS)
async def test_a_name_resolving_to_a_private_address_is_still_refused(db, network, monkeypatch, call):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    network["resolves_to"] = "10.0.0.5"
    with pytest.raises(HTTPException) as exc:
        await call(db)
    assert exc.value.status_code == 400
    assert network["requests"] == [] and network["unrouted"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("call", _CALLS)
async def test_without_a_proxy_the_call_stays_pinned(db, network, call):
    await call(db)
    [req] = network["requests"]
    assert str(req.url) == "https://93.184.216.34/v1/chat/completions" and req.headers["Host"] == _HOST
    assert network["proxies"] == [None] and network["unrouted"] == []
