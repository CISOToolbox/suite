"""Every way out of a "Scan now" run closes the jobs it created ahead.

The route creates a ``pending`` job per scanner before it starts the scan. A
run that stopped early — application disabled or gone, another scan of the
application already running (a ``running`` row, or the in-process lock), the
application disabled mid-scan — left those jobs pending until the stale
sweep, about twenty minutes. Meanwhile "Scan now" answered "scan already in
progress" and the tick skipped the application. They are now closed,
``skipped`` with the reason. Jobs left by a stopped process are failed by
the boot sweep."""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON, event, select  # noqa: E402
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

APP = uuid.uuid4()
USER = "ciso@medsecure.example"
SCANNERS = ["gitleaks", "sast"]
ALREADY_RUNNING = "Another scan of this application was already running"


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
    monkeypatch.setattr(ssrf_guard, "resolve_safe_target", lambda host, **kw: "203.0.113.10")
    monkeypatch.setattr(scanners.subprocess, "run", _git)
    for name in SCANNERS:
        monkeypatch.setitem(scheduler.SCANNERS, name, lambda *a: [])
    async with maker() as db:
        db.add(Application(id=APP, name="MedSecure patient app",
                           repo_url="https://github.com/medsecure/patient.git",
                           enabled_scanners=SCANNERS))
        await db.commit()
    yield maker
    await engine.dispose()


async def _scan_now(maker, app_id=APP):
    """What the route does before it starts the scan."""
    async with maker() as db:
        for name in SCANNERS:
            db.add(ScanJob(id=uuid.uuid4(), application_id=app_id, scanner=name, status="pending",
                           triggered_by=USER, started_at=datetime.now(timezone.utc)))
        await db.commit()


async def _jobs(maker, app_id=APP):
    async with maker() as db:
        return (await db.execute(select(ScanJob).where(ScanJob.application_id == app_id)
                                 .order_by(ScanJob.scanner))).scalars().all()


async def _set_enabled(maker, value):
    async with maker() as db:
        (await db.get(Application, APP)).enabled = value
        await db.commit()


def _closed_as_skipped(jobs, reason):
    assert jobs, "no job"
    for job in jobs:
        assert (job.status, job.error) == ("skipped", reason), (job.scanner, job.status, job.error)
        assert job.completed_at is not None


async def _run(app_id=APP, triggered_by=USER):
    await scheduler._scan_application(app_id, force=True, triggered_by=triggered_by)


@pytest.mark.asyncio
async def test_app_disabled_before_the_scan(mk):
    await _scan_now(mk)
    await _set_enabled(mk, False)
    await _run()
    _closed_as_skipped(await _jobs(mk), "Application disabled")


@pytest.mark.asyncio
async def test_app_gone_before_the_scan(mk):
    # Deleting the application through the API deletes its jobs with it;
    # this covers a row removed underneath.
    gone = uuid.uuid4()
    await _scan_now(mk, gone)
    await _run(gone)
    _closed_as_skipped(await _jobs(mk, gone), "Application not found")


@pytest.mark.asyncio
async def test_a_running_row_already_in_the_database(mk):
    async with mk() as db:
        db.add(ScanJob(id=uuid.uuid4(), application_id=APP, scanner="trivy_fs", status="running",
                       triggered_by="scheduler", started_at=datetime.now(timezone.utc)))
        await db.commit()
    await _scan_now(mk)
    await _run()
    jobs = await _jobs(mk)
    _closed_as_skipped([j for j in jobs if j.triggered_by == USER], ALREADY_RUNNING)
    assert [j.status for j in jobs if j.triggered_by == "scheduler"] == ["running"]


@pytest.mark.asyncio
async def test_the_lock_already_taken_by_a_scheduled_scan(mk):
    await _scan_now(mk)
    async with await scheduler._get_app_lock(APP):
        await _run()
    _closed_as_skipped(await _jobs(mk), ALREADY_RUNNING)


@pytest.mark.asyncio
async def test_a_job_the_running_scan_takes_meanwhile_stays_its_own(mk):
    """The scan holding the lock takes the next pending job (to ``running``)
    while the manual run is closing them: that job is not overwritten."""
    await _scan_now(mk)
    gitleaks = (await _jobs(mk))[0]
    engine = mk.kw["bind"].sync_engine
    fired = []

    def claim_before_the_close(conn, cursor, statement, params, context, executemany):
        if fired or not statement.lstrip().upper().startswith("UPDATE SCAN_JOBS"):
            return
        fired.append(True)
        conn.exec_driver_sql("UPDATE scan_jobs SET status = 'running' WHERE id = ?",
                             (gitleaks.id.hex,))

    event.listen(engine, "before_cursor_execute", claim_before_the_close)
    try:
        async with await scheduler._get_app_lock(APP):
            await _run()
    finally:
        event.remove(engine, "before_cursor_execute", claim_before_the_close)
    assert fired
    gitleaks, sast = await _jobs(mk)
    assert (gitleaks.status, gitleaks.error, gitleaks.completed_at) == ("running", "", None)
    _closed_as_skipped([sast], ALREADY_RUNNING)


@pytest.mark.asyncio
async def test_a_scheduled_run_leaves_the_manual_jobs_alone(mk):
    """The other way round: the manual run holds the lock and will take its
    pending jobs one scanner after the other."""
    await _scan_now(mk)
    async with await scheduler._get_app_lock(APP):
        await _run(triggered_by="scheduler")
    assert [j.status for j in await _jobs(mk)] == ["pending", "pending"]


@pytest.mark.asyncio
async def test_app_disabled_during_the_scan(mk, monkeypatch):
    real = scheduler._run_single_scanner

    async def run_then_disable(**kw):
        await real(**kw)
        await _set_enabled(mk, False)

    monkeypatch.setattr(scheduler, "_run_single_scanner", run_then_disable)
    await _scan_now(mk)
    await _run()
    gitleaks, sast = await _jobs(mk)
    assert gitleaks.status == "completed"
    _closed_as_skipped([sast], "Application disabled during the scan")


@pytest.mark.asyncio
async def test_jobs_of_a_stopped_process_are_failed_at_boot(mk):
    """A process stopped mid-run cannot close anything: the next one fails
    every job created before it started."""
    await _scan_now(mk)
    await scheduler._reset_stale_jobs(
        reason="container restart — job orphaned by previous process",
        only_orphan=False, created_before=datetime.now(timezone.utc) + timedelta(seconds=1))
    for job in await _jobs(mk):
        assert job.status == "failed" and job.completed_at is not None
