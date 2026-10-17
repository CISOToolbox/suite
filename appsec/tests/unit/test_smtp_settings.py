"""FEAT-58 — SMTP is settable in the module itself when Pilot is absent.

The shared router (``src/smtp_settings_common.py``), mounted as AppSec mounts
it, against SQLite. Only the test host names are faked in the resolver; every
numeric notation goes through the real one. Locks:
  - standalone: an admin PUT writes the ``smtp.*`` rows (password encrypted at
    rest) and updates at once the in-memory config the senders read;
  - a blank password keeps the stored one;
  - an empty host removes every ``smtp.*`` row, so the ``SMTP_*`` environment
    applies — port and TLS included — whereas saved values win field by field;
  - GET reports ``password_set``, never the password;
  - suite (``AUTH_MODE=pilot``): PUT is refused with 409;
  - a non-admin cannot write;
  - the host is checked with ssrf_guard: loopback, link-local (metadata),
    unspecified addresses and the suite's own services are refused in every
    notation, a private on-site relay is accepted;
  - the test mail is refused while nothing is configured, sent with the
    resolved config otherwise, and refused if the host turns unsafe by then;
  - AppSec's senders fall back to ``SMTP_*`` and honour ``tls=false``.
"""
from __future__ import annotations

import os
import socket
import sys
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/appsec_test")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import mailer_common, smtp_settings_common  # noqa: E402
from src.auth import get_current_user  # noqa: E402
from src.database import get_db  # noqa: E402
from src.models import AppSettings  # noqa: E402
from src.settings_crypto import is_encrypted  # noqa: E402

_CONFIG = {"host": "smtp.medsecure.example", "port": 587, "user": "ops",
           "password": "s3cret", "from_addr": "appsec@medsecure.example", "tls": True}
_SMTP_ENV = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TLS")
_FAKE_DNS = {"smtp.medsecure.example": "93.184.216.34", "relay.medsecure.example": "10.0.0.25"}
_real_getaddrinfo = socket.getaddrinfo


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Resolve the test names; leave every other lookup to the real resolver."""
    table = dict(_FAKE_DNS)

    def getaddrinfo(host, *args, **kwargs):
        if host in table:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], 0))]
        return _real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return table


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
    """A client on the router as a module mounts it, plus the state it refreshes."""
    for var in _SMTP_ENV:
        monkeypatch.delenv(var, raising=False)
    state: dict = {}

    async def _db():
        async with sessions() as s:
            yield s

    def _make(mode: str = "standalone", role: str = "admin"):
        monkeypatch.setattr(smtp_settings_common, "AUTH_MODE", mode)
        app = FastAPI()
        app.include_router(smtp_settings_common.make_smtp_router(
            state=state, default_from="appsec@cisotoolbox.local"))
        app.dependency_overrides[get_db] = _db
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(_module_role=role)
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")

    return _make, state, sessions


async def _rows(sessions) -> dict[str, str]:
    async with sessions() as s:
        rows = (await s.execute(select(AppSettings).where(AppSettings.key.like("smtp.%")))).scalars()
        return {r.key: r.value for r in rows}


@pytest.mark.asyncio
async def test_standalone_put_writes_rows_and_updates_state(make_client):
    make, state, sessions = make_client
    async with make() as c:
        r = await c.put("/api/smtp/config", json=_CONFIG)
    assert r.status_code == 200
    rows = await _rows(sessions)
    assert rows["smtp.host"] == "smtp.medsecure.example"
    assert rows["smtp.tls"] == "true"
    assert is_encrypted(rows["smtp.password"])  # at rest
    assert state == {"host": "smtp.medsecure.example", "port": "587", "user": "ops",
                     "password": "s3cret", "from_addr": "appsec@medsecure.example", "tls": "true"}


@pytest.mark.asyncio
async def test_blank_password_keeps_the_stored_one(make_client):
    make, state, sessions = make_client
    async with make() as c:
        await c.put("/api/smtp/config", json=_CONFIG)
        r = await c.put("/api/smtp/config", json={**_CONFIG, "password": "", "user": "ops2"})
    assert r.status_code == 200
    assert state["password"] == "s3cret" and state["user"] == "ops2"
    assert is_encrypted((await _rows(sessions))["smtp.password"])


@pytest.mark.asyncio
async def test_empty_host_hands_over_to_the_environment_entirely(make_client, monkeypatch):
    make, state, sessions = make_client
    async with make() as c:
        await c.put("/api/smtp/config", json=_CONFIG)
        # What the UI sends when the form is emptied.
        await c.put("/api/smtp/config", json={"host": "", "port": 587, "user": "", "password": "",
                                              "from_addr": "", "tls": True})
        got = (await c.get("/api/smtp/config")).json()
    assert state == {} and await _rows(sessions) == {}
    assert got["host"] == "" and got["password_set"] is False
    monkeypatch.setenv("SMTP_HOST", "relay.env.example")
    monkeypatch.setenv("SMTP_PORT", "465")
    monkeypatch.setenv("SMTP_TLS", "false")
    cfg = mailer_common.resolve_pushed_config(state, "appsec@cisotoolbox.local")
    assert (cfg["host"], cfg["port"], cfg["tls"]) == ("relay.env.example", 465, False)


def test_saved_values_take_precedence_field_by_field(monkeypatch):
    # The suite-wide contract (Watch locks it too): a value saved/pushed wins,
    # a missing one falls back to its SMTP_* variable.
    monkeypatch.setenv("SMTP_USER", "env-user")
    monkeypatch.setenv("SMTP_PORT", "465")
    cfg = mailer_common.resolve_pushed_config({"host": "smtp.medsecure.example", "user": "ui"}, "x@y.example")
    assert cfg["user"] == "ui" and cfg["port"] == 465


def test_env_credentials_never_go_to_a_saved_host(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "corp-relay.example")
    monkeypatch.setenv("SMTP_USER", "corp-svc")
    monkeypatch.setenv("SMTP_PASSWORD", "corp-secret")
    cfg = mailer_common.resolve_pushed_config({"host": "smtp.medsecure.example"}, "appsec@cisotoolbox.local")
    assert cfg["host"] == "smtp.medsecure.example"
    assert cfg["user"] == "" and cfg["password"] == "" and cfg["from_addr"] == "appsec@cisotoolbox.local"


def test_env_credentials_go_with_the_env_host(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "corp-relay.example")
    monkeypatch.setenv("SMTP_USER", "corp-svc")
    monkeypatch.setenv("SMTP_PASSWORD", "corp-secret")
    cfg = mailer_common.resolve_pushed_config({}, "appsec@cisotoolbox.local")
    assert (cfg["host"], cfg["user"], cfg["password"]) == ("corp-relay.example", "corp-svc", "corp-secret")


@pytest.mark.asyncio
@pytest.mark.parametrize("typed, stored", [("[10.0.0.25]", "10.0.0.25"), ("10.0.0.25.", "10.0.0.25"),
                                           ("relay.medsecure.example.", "relay.medsecure.example")])
async def test_host_is_stored_in_a_form_smtplib_accepts(make_client, typed, stored):
    make, state, _ = make_client
    async with make() as c:
        r = await c.put("/api/smtp/config", json={**_CONFIG, "host": typed})
    assert r.status_code == 200 and state["host"] == stored


@pytest.mark.asyncio
async def test_test_mail_does_not_check_an_environment_host(make_client, monkeypatch):
    # A host from SMTP_* is the operator's, trusted like a Pilot push and like
    # every real send: the test mail reaches it, unchecked.
    make, _, _ = make_client
    monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
    sent = {}
    monkeypatch.setattr(mailer_common, "smtp_deliver", lambda host, port, **kw: sent.update(host=host, **kw))
    async with make() as c:
        r = await c.post("/api/smtp/test", json={"to": "ciso@medsecure.example"})
    assert r.status_code == 200 and sent["host"] == "127.0.0.1" and sent["host_validator"] is None


@pytest.mark.asyncio
async def test_get_reports_password_set_never_the_password(make_client):
    make, _, _ = make_client
    async with make() as c:
        await c.put("/api/smtp/config", json=_CONFIG)
        got = (await c.get("/api/smtp/config")).json()
    assert "password" not in got
    assert got["password_set"] is True and got["managed"] is False
    assert got["host"] == "smtp.medsecure.example" and got["port"] == 587 and got["tls"] is True


@pytest.mark.asyncio
async def test_suite_mode_refuses_writes(make_client):
    make, state, sessions = make_client
    async with make(mode="pilot") as c:
        r = await c.put("/api/smtp/config", json=_CONFIG)
        got = (await c.get("/api/smtp/config")).json()
    assert r.status_code == 409
    assert state == {} and await _rows(sessions) == {}
    assert got["managed"] is True


@pytest.mark.asyncio
async def test_non_admin_cannot_write(make_client):
    make, state, _ = make_client
    async with make(role="viewer") as c:
        assert (await c.put("/api/smtp/config", json=_CONFIG)).status_code == 403
        assert (await c.post("/api/smtp/test", json={"to": "ciso@medsecure.example"})).status_code == 403
    assert state == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.1", "2130706433", "0x7f.1", "0177.0.0.1", "0", "0.0.0.0", "localhost",
    "[::1]", "::ffff:127.0.0.1", "169.254.169.254", "0xa9fea9fe", "2852039166",
    "pilot-db", "surface-app", "smtp\r\nexample", "smtp://x", "user@smtp.example",
])
async def test_unsafe_or_malformed_host_is_refused(make_client, host):
    make, state, _ = make_client
    async with make() as c:
        r = await c.put("/api/smtp/config", json={**_CONFIG, "host": host})
    assert r.status_code == 400, r.text
    assert state == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["10.0.0.25", "relay.medsecure.example", "smtp.medsecure.example"])
async def test_private_or_public_relay_is_accepted(make_client, host):
    make, state, _ = make_client
    async with make() as c:
        r = await c.put("/api/smtp/config", json={**_CONFIG, "host": host})
    assert r.status_code == 200 and state["host"] == host


@pytest.mark.asyncio
async def test_test_mail_refused_while_unconfigured(make_client):
    make, _, _ = make_client
    async with make() as c:
        r = await c.post("/api/smtp/test", json={"to": "ciso@medsecure.example"})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_test_mail_sent_with_the_resolved_config(make_client, monkeypatch):
    make, _, _ = make_client
    sent = {}
    monkeypatch.setattr(mailer_common, "smtp_deliver", lambda host, port, **kw: sent.update(host=host, port=port, **kw))
    async with make() as c:
        await c.put("/api/smtp/config", json=_CONFIG)
        r = await c.post("/api/smtp/test", json={"to": "ciso@medsecure.example"})
    assert r.status_code == 200
    assert sent["host"] == "smtp.medsecure.example" and sent["port"] == 587
    assert sent["recipients"] == ["ciso@medsecure.example"] and sent["host_validator"] is not None


@pytest.mark.asyncio
async def test_test_mail_refused_if_the_host_turned_unsafe(make_client, fake_dns, monkeypatch):
    make, _, _ = make_client
    async with make() as c:
        await c.put("/api/smtp/config", json=_CONFIG)
        fake_dns["smtp.medsecure.example"] = "127.0.0.1"  # rebinding after the save
        connected = []
        monkeypatch.setattr("smtplib.SMTP", lambda *a, **k: connected.append(a))
        r = await c.post("/api/smtp/test", json={"to": "ciso@medsecure.example"})
    text = r.text.lower()
    assert r.status_code == 502 and ("blocked" in text or "refused" in text), r.text
    assert connected == []


def test_appsec_senders_fall_back_to_the_environment(monkeypatch):
    import src.routes.internal as internal
    from src import findings_notify
    monkeypatch.setattr(internal, "_smtp_config", {})
    monkeypatch.setenv("SMTP_HOST", "smtp.medsecure.example")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_TLS", "false")
    cfg = findings_notify._smtp_cfg()
    assert cfg["host"] == "smtp.medsecure.example" and cfg["port"] == 2525
    assert cfg["tls"] is False and cfg["from_addr"] == "appsec@cisotoolbox.local"


def test_appsec_send_honours_tls_false(monkeypatch):
    from src import findings_notify
    seen = {}
    monkeypatch.setattr(mailer_common, "smtp_deliver", lambda *a, **kw: seen.update(kw))
    findings_notify._send_email(
        {"host": "smtp.medsecure.example", "port": 25, "user": "", "password": "",
         "from_addr": "appsec@medsecure.example", "tls": False},
        "ciso@medsecure.example", "subject", "<p>x</p>")
    assert seen["use_tls"] is False
