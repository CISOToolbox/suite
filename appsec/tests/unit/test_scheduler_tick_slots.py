"""The tick's MAX_PER_TICK slots go to applications that are due.

The tick takes the enabled applications oldest ``last_scan_at`` first. It
used to cut that list to MAX_PER_TICK before dropping the ones whose
frequency had not elapsed or that already had a job running or pending: an
application on a weekly frequency, last scanned before the others, held a
slot without being scanned, and MAX_PER_TICK such applications kept every
other one waiting for ever."""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import src.database as database  # noqa: E402
import src.scheduler as scheduler  # noqa: E402
from src.models import Application, Base, ScanJob  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

DUE = uuid.uuid4()


class _RecordingAsyncio:
    """``asyncio`` as the scheduler sees it; ``create_task`` records which
    application the tick scheduled and starts nothing."""

    def __init__(self):
        self.scheduled = []

    def create_task(self, coro):
        self.scheduled.append(coro.cr_frame.f_locals["app_id"])
        coro.close()

    def __getattr__(self, name):
        return getattr(asyncio, name)


class _NaiveUtc(datetime):
    """SQLite hands ``last_scan_at`` back without its time zone (PostgreSQL
    keeps it): the tick computes in naive UTC here so the two compare."""

    @classmethod
    def now(cls, tz=None):
        return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest_asyncio.fixture
async def mk(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(database, "async_session", maker)
    monkeypatch.setattr(scheduler, "async_session", maker)
    monkeypatch.setattr(scheduler, "datetime", _NaiveUtc)
    yield maker
    await engine.dispose()


async def _tick(monkeypatch):
    fake = _RecordingAsyncio()
    monkeypatch.setattr(scheduler, "asyncio", fake)
    await scheduler._tick()
    return fake.scheduled


async def _add_due_app(db, now):
    # Daily, last scanned 30 hours ago: due, but more recent than the others.
    db.add(Application(id=DUE, name="MedSecure patient app",
                       repo_url="https://github.com/medsecure/patient.git",
                       enabled_scanners=["gitleaks"], scan_frequency_hours=24,
                       last_scan_at=now - timedelta(hours=30)))


@pytest.mark.asyncio
async def test_apps_not_due_do_not_hold_the_slots(mk, monkeypatch):
    now = datetime.now(timezone.utc)
    async with mk() as db:
        for i in range(scheduler.MAX_PER_TICK):
            # Weekly, last scanned two days ago: older than the due app, not due.
            db.add(Application(name=f"MedSecure weekly app {i}",
                               repo_url=f"https://github.com/medsecure/weekly-{i}.git",
                               enabled_scanners=["gitleaks"], scan_frequency_hours=168,
                               last_scan_at=now - timedelta(hours=48 + i)))
        await _add_due_app(db, now)
        await db.commit()
    assert await _tick(monkeypatch) == [DUE]


@pytest.mark.asyncio
async def test_apps_already_scanning_do_not_hold_the_slots(mk, monkeypatch):
    now = datetime.now(timezone.utc)
    async with mk() as db:
        for i, status in enumerate(["pending", "running"][:scheduler.MAX_PER_TICK]):
            app = Application(name=f"MedSecure busy app {i}",
                              repo_url=f"https://github.com/medsecure/busy-{i}.git",
                              enabled_scanners=["gitleaks"], scan_frequency_hours=24,
                              last_scan_at=now - timedelta(hours=72 + i))
            db.add(app)
            await db.flush()
            db.add(ScanJob(application_id=app.id, scanner="gitleaks", status=status,
                           triggered_by="scheduler", started_at=now))
        await _add_due_app(db, now)
        await db.commit()
    assert await _tick(monkeypatch) == [DUE]


@pytest.mark.asyncio
async def test_the_oldest_due_apps_go_first(mk, monkeypatch):
    now = datetime.now(timezone.utc)
    ids = []
    async with mk() as db:
        for i in range(scheduler.MAX_PER_TICK + 1):
            app = Application(id=uuid.uuid4(), name=f"MedSecure daily app {i}",
                              repo_url=f"https://github.com/medsecure/daily-{i}.git",
                              enabled_scanners=["gitleaks"], scan_frequency_hours=24,
                              last_scan_at=now - timedelta(hours=40 - i))
            db.add(app)
            ids.append(app.id)
        await db.commit()
    assert await _tick(monkeypatch) == ids[:scheduler.MAX_PER_TICK]


@pytest.mark.asyncio
async def test_apps_whose_scan_holds_the_lock_do_not_hold_the_slots(mk, monkeypatch):
    """A planned scan in ``ls-remote`` or cloning has no ``running`` row yet
    and its ``last_scan_at`` has not moved: the next tick must not plan it
    again (the second run would stop on the lock, its slot wasted)."""
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(scheduler, "_app_locks", {})
    async with mk() as db:
        for i in range(scheduler.MAX_PER_TICK):
            app = Application(id=uuid.uuid4(), name=f"MedSecure cloning app {i}",
                              repo_url=f"https://github.com/medsecure/cloning-{i}.git",
                              enabled_scanners=["gitleaks"], scan_frequency_hours=24,
                              last_scan_at=now - timedelta(hours=72 + i))
            db.add(app)
            lock = asyncio.Lock()
            await lock.acquire()
            scheduler._app_locks[app.id] = lock
        await _add_due_app(db, now)
        await db.commit()
    assert await _tick(monkeypatch) == [DUE]
