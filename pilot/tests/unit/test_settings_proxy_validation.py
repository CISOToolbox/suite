"""BUG-92 — Pilot validates the outbound proxy settings before pushing them.

The proxy exceptions (``no_proxy``) are an exception list: IPs, domains
(which cover their subdomains), ``*.domain`` / ``.domain``, an optional
``:port``, or ``*``. A range is refused: httpx would accept it in NO_PROXY
and never apply it.
Pilot stored whatever was typed and every module either refused it (the save
then read "ok") or exported an entry httpx cannot parse, which breaks every
HTTP client of the module. Locks, through ``update_settings`` against SQLite:
  - an invalid entry is refused with 400 naming it, and nothing is stored;
  - a valid list is stored normalized, as the modules receive it;
  - a proxy value that is not one URL is refused.
"""
import os
import sys

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


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


async def _stored(db, key: str):
    row = (await db.execute(select(AppSettings).where(AppSettings.key == key))).scalar_one_or_none()
    return row.value if row else None


@pytest.mark.asyncio
@pytest.mark.parametrize("value, entry", [("localhost,bad entry", "bad entry"), ("10.0.0.0/8", "10.0.0.0/8"),
                                          ("http://proxy.medsecure.example", "http://proxy.medsecure.example")])
async def test_an_invalid_exception_is_refused(db, value, entry):
    with pytest.raises(HTTPException) as exc:
        await settings.update_settings(settings.SettingsUpdate(no_proxy=value), user=None, db=db)
    assert exc.value.status_code == 400
    assert "no_proxy" in exc.value.detail
    assert repr(entry) in exc.value.detail  # the admin is told which one
    assert await _stored(db, "no_proxy") is None


@pytest.mark.asyncio
async def test_a_valid_exception_list_is_stored_as_the_modules_get_it(db):
    resp = await settings.update_settings(settings.SettingsUpdate(
        no_proxy="localhost, *.medsecure.local,.lab.example,10.4.2.1,[::1],ldap.medsecure.example:636"),
        user=None, db=db)
    assert resp["ok"] is True
    assert await _stored(db, "no_proxy") == "localhost,medsecure.local,lab.example,10.4.2.1,::1,ldap.medsecure.example:636"


@pytest.mark.asyncio
async def test_a_proxy_value_that_is_not_one_url_is_refused(db):
    with pytest.raises(HTTPException) as exc:
        await settings.update_settings(settings.SettingsUpdate(
            https_proxy="http://proxy.medsecure.example:3128,http://127.0.0.1:8080"), user=None, db=db)
    assert exc.value.status_code == 400
    assert await _stored(db, "https_proxy") is None


@pytest.mark.asyncio
async def test_no_secret_is_returned_by_the_settings_route(db):
    """GET /settings masked secrets by name ("key_" in it): the custom LLM key
    matched no pattern and went back to the browser in clear, and the screen
    never offered to clear it."""
    from src.settings_crypto import is_secret_key
    secrets = [k for k in settings.SETTINGS_KEYS if is_secret_key(k)]
    assert "ai_custom_key" in secrets
    for key in secrets:
        await settings._set_setting(key, "s3cr", db)  # short ones too
    await db.commit()
    got = await settings.get_settings(user=None, db=db)
    assert {k: got[k] for k in secrets} == {k: "configured" for k in secrets}


@pytest.mark.asyncio
async def test_the_custom_llm_is_validated_with_its_stored_key(db, monkeypatch):
    """The screen does not send back a key it shows as bullets: validating the
    endpoint without it was refused by any LLM that requires one, and every
    save of the settings page failed with it."""
    await settings._set_setting("ai_custom_endpoint", "https://api.mistral.ai/v1", db)
    await settings._set_setting("ai_custom_key", "sk-medsecure-llm", db)
    await db.commit()
    seen = {}

    async def validate(provider, key, endpoint="", model="", **_kw):
        seen["key"] = key
        return True, ""

    monkeypatch.setattr(settings, "_validate_ai_key", validate)
    monkeypatch.setattr(settings, "_validate_endpoint_url", lambda url, proxies: None)
    await settings.update_settings(settings.SettingsUpdate(
        ai_custom_endpoint="https://api.mistral.ai/v1", ai_custom_model="mistral-small-latest"), user=None, db=db)
    assert seen["key"] == "sk-medsecure-llm"

