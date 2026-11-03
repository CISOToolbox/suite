"""An application whose repository cannot be reached never starves the others.

The scheduler takes MAX_PER_TICK applications per tick, oldest
``last_scan_at`` first. A planned scan first asks git for the remote head;
when the host re-check refuses the URL there, the scan used to crash before
writing anything: no failed job in the history, ``last_scan_at`` unchanged,
so the same applications headed every tick and the others were never
scanned. A refused head check now ends like a failed clone: a visible failed
job per repo scanner, ``last_scan_at`` advanced. The image scan, which does
not need the repository, still runs in both cases."""
import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

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

import src.database as database  # noqa: E402
import src.scanners as scanners  # noqa: E402
import src.scheduler as scheduler  # noqa: E402
import src.ssrf_guard as ssrf_guard  # noqa: E402
from src.models import Application, Base, ScanJob  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

GONE = {"gone-a.example", "gone-b.example"}
BAD_A, BAD_B, GOOD = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def _resolve(host, **kw):
    if host in GONE:
        raise ValueError(f"cannot resolve {host}")
    return "203.0.113.10"


def _git(cmd, **kw):
    if cmd[1] == "ls-remote":
        return SimpleNamespace(returncode=0, stdout="0123abcd\trefs/heads/main\n", stderr="")
    return SimpleNamespace(returncode=0, stdout="", stderr="")  # clone into the temp dir


@pytest_asyncio.fixture
async def mk(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(database, "async_session", maker)
    monkeypatch.setattr(scheduler, "async_session", maker)
    monkeypatch.setattr(scheduler, "_app_locks", {})
    monkeypatch.setattr(scheduler, "_app_locks_mutex", asyncio.Lock())
    monkeypatch.setattr(ssrf_guard, "resolve_safe_target", _resolve)
    monkeypatch.setattr(scanners.subprocess, "run", _git)
    monkeypatch.setitem(scheduler.SCANNERS, "gitleaks", lambda *a: [])
    monkeypatch.setattr(scheduler, "run_trivy_image", lambda *a: ([], []))
    async with maker() as db:
        # Never scanned: the two broken apps come first in the tick order.
        db.add(Application(id=BAD_A, name="MedSecure legacy portal",
                           repo_url="https://gone-a.example/medsecure/portal.git",
                           enabled_scanners=["gitleaks"]))
        db.add(Application(id=BAD_B, name="MedSecure device API",
                           repo_url="https://gone-b.example/medsecure/api.git",
                           enabled_scanners=["gitleaks", "trivy_image"],
                           docker_images=["ghcr.io/medsecure/api:1"]))
        db.add(Application(id=GOOD, name="MedSecure patient app",
                           repo_url="https://github.com/medsecure/patient.git",
                           enabled_scanners=["gitleaks"]))
        await db.commit()
    yield maker
    await engine.dispose()


class _QueuedAsyncio:
    """``asyncio`` as the scheduler sees it, except that ``create_task``
    queues the scan instead of starting it.

    StaticPool hands every session the same SQLite connection, so two scans
    running at once share one transaction: one session closing rolls back
    what the other has flushed but not yet committed, and a failed job
    vanishes depending on thread timing. The test runs the tick's scans one
    after the other instead (production sessions each get their own
    connection)."""

    def __init__(self):
        self.queued = []

    def create_task(self, coro):
        self.queued.append(coro)

    def __getattr__(self, name):
        return getattr(asyncio, name)


async def _jobs(maker, app_id):
    async with maker() as db:
        return {(j.scanner, j.status): j for j in (await db.execute(
            select(ScanJob).where(ScanJob.application_id == app_id))).scalars().all()}


@pytest.mark.asyncio
async def test_unreachable_repos_do_not_starve_the_valid_app(mk, monkeypatch):
    fake = _QueuedAsyncio()
    monkeypatch.setattr(scheduler, "asyncio", fake)
    scheduled = []
    for _ in range(3):
        await scheduler._tick()
        scheduled.append(len(fake.queued))
        while fake.queued:
            await fake.queued.pop(0)
    # MAX_PER_TICK = 2: the two broken apps first, then the valid one.
    assert scheduled == [2, 1, 0]

    good = await _jobs(mk, GOOD)
    assert ("gitleaks", "completed") in good

    for app_id in (BAD_A, BAD_B):
        jobs = await _jobs(mk, app_id)
        failed = jobs.get(("gitleaks", "failed"))
        assert failed is not None
        assert "not allowed" in failed.error
        assert failed.triggered_by == "scheduler"
        async with mk() as db:
            assert (await db.get(Application, app_id)).last_scan_at is not None


@pytest.mark.asyncio
async def test_refused_head_check_still_runs_the_image_scan(mk):
    await scheduler._scan_application(BAD_B)
    jobs = await _jobs(mk, BAD_B)
    assert set(jobs) == {("gitleaks", "failed"), ("trivy_image", "completed")}


@pytest.mark.asyncio
async def test_failed_clone_still_runs_the_image_scan(mk):
    # A manual scan skips the head check: the clone's own host re-check fails.
    await scheduler._scan_application(BAD_B, force=True, triggered_by="admin@medsecure.example")
    jobs = await _jobs(mk, BAD_B)
    assert set(jobs) == {("gitleaks", "failed"), ("trivy_image", "completed")}
    assert jobs[("gitleaks", "failed")].triggered_by == "admin@medsecure.example"
    async with mk() as db:
        assert (await db.get(Application, BAD_B)).last_scan_at is not None


@pytest.mark.asyncio
async def test_failed_clone_takes_over_the_pending_jobs_of_scan_now(mk):
    # "Scan now" creates a pending job per scanner before the scan starts; a
    # left-over pending row would answer scan_already_in_progress for ~20 min.
    who = "admin@medsecure.example"
    async with mk() as db:
        for scanner_name in ("gitleaks", "trivy_image"):
            db.add(ScanJob(id=uuid.uuid4(), application_id=BAD_B, scanner=scanner_name,
                           status="pending", triggered_by=who))
        await db.commit()
    await scheduler._scan_application(BAD_B, force=True, triggered_by=who)
    async with mk() as db:
        rows = (await db.execute(
            select(ScanJob).where(ScanJob.application_id == BAD_B))).scalars().all()
    assert sorted((j.scanner, j.status) for j in rows) == [
        ("gitleaks", "failed"), ("trivy_image", "completed")]
    assert all(j.completed_at is not None for j in rows)
    assert "not allowed" in next(j.error for j in rows if j.scanner == "gitleaks")


@pytest.mark.asyncio
async def test_head_check_refused_after_the_scan_keeps_last_scan_at(mk, monkeypatch):
    # The clone passed the re-check; the host stops resolving before the
    # head lookup that records last_scan_commit.
    calls = []

    def flaky(host, **kw):
        calls.append(host)
        if len(calls) > 1:
            raise ValueError(f"cannot resolve {host}")
        return "203.0.113.10"

    monkeypatch.setattr(ssrf_guard, "resolve_safe_target", flaky)
    await scheduler._scan_application(GOOD, force=True, triggered_by="admin@medsecure.example")
    assert ("gitleaks", "completed") in await _jobs(mk, GOOD)
    async with mk() as db:
        app = await db.get(Application, GOOD)
    assert app.last_scan_at is not None
    assert not app.last_scan_commit
