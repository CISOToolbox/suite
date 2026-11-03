"""Regression: deleting an account in Pilot must take its address out of every
application's `notification_emails`.

That list, keyed by email, decides who receives finding alerts and the weekly
recap. Left there, the next holder of the address received them — with every
alert on, since Pilot drops the preferences and an address without any gets
the defaults.
"""
import os
import sys
import uuid

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import src.audit_common as audit_mod  # noqa: E402
from src.models import Application, Base, User  # noqa: E402
from src.routes import internal  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

pytestmark = pytest.mark.asyncio

_TOKEN = "svc-token-for-tests-0123456789abcdef"
_EMAIL = "alice@medsecure.example"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    async def _noop(*_a, **_k):
        return None
    monkeypatch.setattr(audit_mod, "log_write", _noop)
    monkeypatch.setattr(internal, "SERVICE_TOKEN", _TOKEN)


class _Req:
    headers = {"X-Service-Token": _TOKEN}

    def __init__(self, email):
        self._email = email

    async def json(self):
        return {"email": self._email}


async def _apps(db):
    portal = Application(id=uuid.uuid4(), name="Patient portal",
                         notification_emails=["Alice@MedSecure.example", "bob@medsecure.example"])
    api = Application(id=uuid.uuid4(), name="Device API", notification_emails=[_EMAIL])
    other = Application(id=uuid.uuid4(), name="Intranet", notification_emails=["bob@medsecure.example"])
    db.add_all([portal, api, other])
    await db.commit()
    return portal.id, api.id, other.id


async def _emails(db, app_id):
    # get_db does not commit: whatever the route left uncommitted is lost.
    await db.rollback()
    return (await db.execute(select(Application.notification_emails)
                             .where(Application.id == app_id))).scalar_one()


async def test_address_leaves_every_recipient_list(db):
    portal, api, other = await _apps(db)
    db.add(User(id=uuid.uuid4(), email=_EMAIL, name="Alice", role="user"))
    await db.commit()
    resp = await internal.delete_user(_Req(_EMAIL), db)
    assert await _emails(db, portal) == ["bob@medsecure.example"]
    assert await _emails(db, api) == []
    assert await _emails(db, other) == ["bob@medsecure.example"]
    assert resp["deleted"] is True
    assert resp["applications_unsubscribed"] == 2


async def test_address_without_account_leaves_the_lists_too(db):
    portal, api, _ = await _apps(db)
    resp = await internal.delete_user(_Req(_EMAIL), db)
    assert resp["deleted"] is True
    assert await _emails(db, portal) == ["bob@medsecure.example"]
    assert await _emails(db, api) == []
