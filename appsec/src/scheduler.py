"""Background scheduler: runs enabled scans for each application on schedule."""
from __future__ import annotations

import asyncio
import glob
import logging
import os
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session
from src.models import Application, Finding, ScanJob, SBOMEntry
from src.findings_dedup import upsert_findings
from src.scanners import _clone_repo, _cleanup, get_remote_head, SCANNERS, run_trivy_fs, run_trivy_image, SCAN_TIMEOUT

logger = logging.getLogger("appsec-scheduler")

TICK_SECONDS = 60
MAX_PER_TICK = 2
INITIAL_DELAY = 15

# Buffer added on top of the per-scanner subprocess timeout before a
# "running" job is declared stale. Covers DB writes, ignore-rule
# evaluation, dedup upsert and SBOM write that run after the
# subprocess returns. 5 minutes is generous enough that a slow
# completed scanner does not get its job nuked while finalising.
STALE_JOB_BUFFER_SECONDS = 300

# Stale /tmp/appsec-* clone directories left behind by killed workers.
# Each one is a shallow git clone (tens to hundreds of MB). Without
# this sweep, the host eventually runs out of inodes/space and
# ``tempfile.mkdtemp`` starts raising.
TMP_PREFIX = "appsec-"
TMP_MAX_AGE_SECONDS = 3600  # 1 hour

# Per-app in-process mutex. Prevents two ``_do_scan`` coroutines from
# running concurrently on the same application (e.g. tick scheduler
# firing at the same instant as a manual trigger, or a user clicking
# "Scan now" twice). The lock lives for one process lifetime — the
# boot-sweep handles zombies left by previous processes.
_app_locks: dict[uuid.UUID, asyncio.Lock] = {}
_app_locks_mutex = asyncio.Lock()

# Captured at ``start_scheduler`` time so the boot recovery can tell
# zombies from jobs that user code legitimately created during the
# scheduler's ``INITIAL_DELAY`` warmup. Without it, a user who triggers
# a scan in the first ~15 seconds after restart sees their job killed
# by the boot sweep.
_SCHEDULER_BOOT_TIME: datetime | None = None


async def _get_app_lock(app_id: uuid.UUID) -> asyncio.Lock:
    """Return the asyncio.Lock for an app, creating it on first use."""
    async with _app_locks_mutex:
        lock = _app_locks.get(app_id)
        if lock is None:
            lock = asyncio.Lock()
            _app_locks[app_id] = lock
        return lock


def _cleanup_orphan_tempdirs() -> int:
    """Delete /tmp/appsec-* directories older than TMP_MAX_AGE_SECONDS.

    Called on scheduler boot and every tick. Synchronous because each
    ``rmtree`` is fast and we don't want to add an executor hop.
    """
    removed = 0
    cutoff = time.time() - TMP_MAX_AGE_SECONDS
    base = tempfile.gettempdir()
    try:
        for path in glob.glob(os.path.join(base, TMP_PREFIX + "*")):
            try:
                if not os.path.isdir(path):
                    continue
                if os.path.getmtime(path) >= cutoff:
                    continue
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
            except OSError:
                continue
    except Exception as e:
        logger.warning("Orphan tempdir cleanup error: %s", e)
    return removed


async def _run_single_scanner(
    *, app_id: uuid.UUID, app_name: str, scanner_name: str,
    repo_dir: str | None, scan_paths: list[str],
    docker_images: list[str], image_token_encrypted: str,
    triggered_by: str,
) -> None:
    """Run one scanner in its own DB session so a crash never corrupts
    other scanners or the main session."""
    from src.database import async_session as _mk_session
    async with _mk_session() as db:
        # Reuse the OLDEST pending job for this (app, scanner) and
        # mark every other pending duplicate as ``skipped``. Without
        # this, a user who clicks "Scan now" three times in a row
        # leaves N-1 abandoned pending rows that the scheduler tick
        # then mistakes for active work and refuses to schedule the
        # app until they age out (~20 minutes).
        pending_q = await db.execute(
            select(ScanJob).where(
                ScanJob.application_id == app_id,
                ScanJob.scanner == scanner_name,
                ScanJob.status == "pending",
            ).order_by(ScanJob.created_at.asc())
        )
        pending_jobs = pending_q.scalars().all()
        now = datetime.now(timezone.utc)
        if pending_jobs:
            job = pending_jobs[0]
            for dup in pending_jobs[1:]:
                dup.status = "skipped"
                dup.error = "Superseded by another pending scan job"
                dup.completed_at = now
            if len(pending_jobs) > 1:
                logger.info("Deduped %d superseded pending job(s) for %s/%s",
                            len(pending_jobs) - 1, app_name, scanner_name)
        else:
            job = ScanJob(
                id=uuid.uuid4(), application_id=app_id,
                scanner=scanner_name, triggered_by=triggered_by,
            )
            db.add(job)
        job.status = "running"
        job.started_at = now
        await db.commit()
        # Manual triggers journal in their route (scan.trigger); scheduler
        # runs journal here so every scan execution has an author.
        if triggered_by == "scheduler":
            from src.audit_common import log_write
            await log_write(db, None, None, "scan.auto_trigger", actor="scheduler",
                            entity_type="scan_job", entity_id=str(job.id),
                            target=f"{app_name}/{scanner_name}", commit=True)
        # Capture the id locally so the error handler below can address
        # the row without touching ORM attributes on ``job`` — accessing
        # an expired attribute after a flush failure re-triggers the
        # same IntegrityError and turns "mark as failed" into a second
        # crash, leaving the row stuck in ``running``.
        job_id = job.id

        try:
            all_findings: list[dict] = []
            sbom_data: list[dict] = []

            # Did the scanner actually inspect something? An empty result is
            # meaningful ("nothing vulnerable left") ONLY if it ran. Without
            # this flag, an application with no docker image configured would
            # look like "every image finding is gone" and close the backlog.
            scanner_ran = False
            scan_started = datetime.now(timezone.utc)

            if scanner_name == "trivy_fs" and repo_dir:
                findings, sbom_data = await asyncio.to_thread(
                    run_trivy_fs, repo_dir, str(app_id), scan_paths)
                all_findings.extend(findings)
                scanner_ran = True
            elif scanner_name == "trivy_image":
                for image in docker_images:
                    img_findings, img_sbom = await asyncio.to_thread(
                        run_trivy_image, image, str(app_id), image_token_encrypted)
                    all_findings.extend(img_findings)
                    sbom_data.extend(img_sbom)
                    scanner_ran = True
            elif scanner_name in ("gitleaks", "semgrep") and repo_dir:
                func = SCANNERS.get(scanner_name)
                if func:
                    findings = await asyncio.to_thread(
                        func, repo_dir, str(app_id), scan_paths)
                    all_findings.extend(findings)
                    scanner_ran = True

            # Apply ignore rules before upsert.
            from src.ignore_engine import load_rules, apply_ignore_rules
            rules = await load_rules(db, app_id)
            all_findings, ignored_count = apply_ignore_rules(all_findings, rules)
            if ignored_count:
                logger.info("Ignore rules: %d finding(s) auto-triaged for %s",
                            ignored_count, app_name)

            stats = await upsert_findings(db, app_id, all_findings)
            if sbom_data:
                await _upsert_sbom(db, app_id, sbom_data)
            if scanner_ran:
                stats["closed"] = await _close_unseen_findings(
                    db, app_id, scanner_name, scan_started)

            job.status = "completed"
            job.findings_count = len(all_findings)
            job.diff = stats
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()

            # FEAT-35 — email the app's recipients about findings first
            # seen by this run. Never raises (guarded inside).
            from src.findings_notify import notify_scan_new_findings
            await notify_scan_new_findings(db, job)

        except Exception as e:
            logger.error("Scanner %s failed for app %s: %s",
                         scanner_name, app_name, e, exc_info=True)
            # The outer session may be poisoned (autoflush IntegrityError
            # leaves it in a rolled-back state). Roll it back explicitly
            # so subsequent ``async with __aexit__`` doesn't raise again,
            # and use a brand-new session to flip the row.
            try:
                await db.rollback()
            except Exception:
                pass
            try:
                async with _mk_session() as err_db:
                    failed_job = await err_db.get(ScanJob, job_id)
                    if failed_job:
                        failed_job.status = "failed"
                        failed_job.error = str(e)[:2000]
                        failed_job.completed_at = datetime.now(timezone.utc)
                    await err_db.commit()
            except Exception as e2:
                logger.error("Failed to mark job %s as failed: %s", job_id, e2)


async def _scan_application(app_id: uuid.UUID, force: bool = False, triggered_by: str = "scheduler") -> None:
    logger.info("Scan starting for app_id=%s force=%s triggered_by=%s", app_id, force, triggered_by)
    try:
        await _do_scan(app_id, force, triggered_by)
    except Exception as e:
        logger.error("Scan crashed for app_id=%s: %s", app_id, e, exc_info=True)

async def _do_scan(app_id: uuid.UUID, force: bool, triggered_by: str) -> None:
    # In-process mutex per app — atomic because the check and the
    # ``async with`` acquire happen without any intervening await
    # (asyncio is single-threaded). Two ``_do_scan`` tasks that race
    # on the same app: first acquires, second sees ``locked()`` and
    # returns instead of cloning the repo and racing on
    # ``upsert_findings`` writes.
    lock = await _get_app_lock(app_id)
    if lock.locked():
        logger.info("Scan already in progress for %s (in-process lock), skipping", app_id)
        return
    async with lock:
        await _do_scan_locked(app_id, force, triggered_by)


async def _do_scan_locked(app_id: uuid.UUID, force: bool, triggered_by: str) -> None:
    async with async_session() as db:
        result = await db.execute(select(Application).where(Application.id == app_id))
        app = result.scalar_one_or_none()
        if not app or not app.enabled:
            logger.warning("Scan aborted: app %s not found or disabled", app_id)
            return

        # Belt-and-braces DB-side check on top of the asyncio lock.
        # A "running" row from a previous process that the boot sweep
        # missed (created post-boot-time) would still block here.
        running_q = await db.execute(
            select(ScanJob).where(
                ScanJob.application_id == app.id,
                ScanJob.status == "running",
            ).limit(1)
        )
        if running_q.scalar_one_or_none():
            logger.info("Scan already running for %s (DB row), skipping", app.name)
            return

        scanners = app.enabled_scanners or []
        repo_dir = None
        needs_repo = any(s in scanners for s in ("trivy_fs", "gitleaks", "semgrep"))
        has_image_scan = "trivy_image" in scanners and (app.docker_images or [])

        # Check if repo has new commits since last scan
        if needs_repo and app.repo_url and not force:
            remote_head = await asyncio.to_thread(
                get_remote_head, app.repo_url, app.repo_branch, app.repo_token_encrypted
            )
            if remote_head and remote_head == (app.last_scan_commit or ""):
                # Record a "skipped" job per repo-based scanner so the
                # scan history reflects that the scheduler did run but
                # had nothing to do. Without these rows, scheduler runs
                # would be invisible in the UI between real scans.
                skipped_scanners = [s for s in scanners
                                    if s in ("trivy_fs", "gitleaks", "semgrep")]
                now = datetime.now(timezone.utc)
                skip_reason = f"No new commits since last scan (HEAD={remote_head[:8]})"
                for scanner_name in skipped_scanners:
                    db.add(ScanJob(
                        id=uuid.uuid4(), application_id=app.id,
                        scanner=scanner_name, status="skipped",
                        started_at=now, completed_at=now,
                        findings_count=0, error=skip_reason,
                        triggered_by=triggered_by,
                    ))
                await db.commit()

                if not has_image_scan:
                    logger.info("Skip %s: no new commits (HEAD=%s)", app.name, remote_head[:8])
                    # No new commit — all existing findings are still present.
                    # Touch last_seen_at on active findings and reopen "fixed"
                    # ones (the code hasn't changed so the fix didn't land).
                    # False positives are left untouched.
                    from sqlalchemy import update as sa_update
                    from src.database import async_session as _mk_session
                    async with _mk_session() as touch_db:
                        await touch_db.execute(
                            sa_update(Finding)
                            .where(Finding.application_id == app.id,
                                   Finding.status.in_(["new", "to_fix"]))
                            .values(last_seen_at=now)
                        )
                        # Reopen "fixed" findings — no commit means no fix
                        reopened = await touch_db.execute(
                            sa_update(Finding)
                            .where(Finding.application_id == app.id,
                                   Finding.status == "fixed")
                            .values(status="new", last_seen_at=now,
                                    triaged_at=None, triaged_by=None,
                                    triage_notes="")
                        )
                        if reopened.rowcount:
                            logger.info("Reopened %d fixed finding(s) for %s (no new commits)",
                                        reopened.rowcount, app.name)
                        app_ref = await touch_db.get(Application, app.id)
                        if app_ref:
                            app_ref.last_scan_at = now
                        await touch_db.commit()
                    return
                # Only image scans needed, skip repo scanners
                scanners = [s for s in scanners if s not in ("trivy_fs", "gitleaks", "semgrep")]
                needs_repo = False

        try:
            if needs_repo and app.repo_url:
                try:
                    repo_dir = await asyncio.to_thread(
                        _clone_repo, app.repo_url, app.repo_branch, app.repo_token_encrypted
                    )
                except RuntimeError as clone_err:
                    logger.error("Clone failed for %s: %s", app.name, clone_err)
                    for scanner_name in [s for s in scanners if s in ("trivy_fs", "gitleaks", "semgrep")]:
                        job = ScanJob(
                            id=uuid.uuid4(), application_id=app.id, scanner=scanner_name,
                            status="failed", started_at=datetime.now(timezone.utc),
                            completed_at=datetime.now(timezone.utc),
                            error=str(clone_err)[:2000], triggered_by="scheduler",
                        )
                        db.add(job)
                    app.last_scan_at = datetime.now(timezone.utc)
                    await db.commit()
                    return

            from src.database import async_session as _mk_session
            for scanner_name in scanners:
                # If the admin flipped ``enabled`` off mid-scan, stop
                # before kicking off the next scanner. Already-running
                # scanners finish naturally; only the queued ones are
                # short-circuited.
                async with _mk_session() as chk:
                    cur = await chk.get(Application, app_id)
                    if not cur or not cur.enabled:
                        logger.info("Scan halted mid-flight: %s disabled", app.name)
                        break
                await _run_single_scanner(
                    app_id=app.id, app_name=app.name,
                    scanner_name=scanner_name, repo_dir=repo_dir,
                    scan_paths=app.scan_paths or [],
                    docker_images=app.docker_images or [],
                    image_token_encrypted=getattr(app, "image_token_encrypted", "") or "",
                    triggered_by=triggered_by,
                )

            # Update last_scan_at with a fresh session (main session
            # is not used for scanner work anymore).
            from src.database import async_session as _mk_session
            async with _mk_session() as ts_db:
                ts_app = await ts_db.get(Application, app_id)
                if ts_app:
                    ts_app.last_scan_at = datetime.now(timezone.utc)
                    if repo_dir and app.repo_url:
                        head = await asyncio.to_thread(
                            get_remote_head, app.repo_url, app.repo_branch,
                            app.repo_token_encrypted,
                        )
                        if head:
                            ts_app.last_scan_commit = head
                await ts_db.commit()

        finally:
            if repo_dir:
                _cleanup(repo_dir)


async def _close_unseen_findings(db: AsyncSession, app_id: uuid.UUID,
                                 scanner_name: str, scan_started) -> int:
    """Close the findings this scanner no longer reports.

    The SBOM has always dropped packages that disappeared
    (``_upsert_sbom`` deletes on ``last_seen_at < now``); findings never
    had the equivalent, so a vulnerability that was resolved — typically a
    dependency upgraded past it — stayed on the board for ever, in whatever
    status it carried. A triage list then mixes today's facts with fossils:
    the operator re-triages the same package release after release and the
    verdict never sticks, which is what this looked like from the UI.

    Marked ``fixed``, not deleted: the history and the linked measure are
    worth keeping, ``upsert_findings`` already reopens a ``fixed`` finding
    if it comes back, and the retention pass purges them later.

    Scoped to ONE scanner: a semgrep run must not close SCA findings. Only
    ever called on the success path, and only when the scanner actually
    inspected something.

    A verdict that must survive a version change belongs in an ignore rule
    (criterion `package`, e.g. `lodash@*`), not in per-finding triage —
    a finding is about one package AT one version.
    """
    from sqlalchemy import update as sa_update
    result = await db.execute(
        sa_update(Finding)
        .where(Finding.application_id == app_id,
               Finding.scanner == scanner_name,
               Finding.status != "fixed",
               Finding.last_seen_at < scan_started)
        .values(status="fixed", updated_at=datetime.now(timezone.utc))
    )
    if result.rowcount:
        logger.info("Closed %d finding(s) no longer reported by %s for app %s",
                    result.rowcount, scanner_name, app_id)
    return result.rowcount or 0


async def _upsert_sbom(db: AsyncSession, app_id: uuid.UUID, entries: list[dict]) -> None:
    now = datetime.now(timezone.utc)
    # Bulk-fetch all existing SBOM entries for this app in one query.
    result = await db.execute(
        select(SBOMEntry).where(SBOMEntry.application_id == app_id)
    )
    existing_map: dict[tuple[str, str], SBOMEntry] = {}
    for row in result.scalars().all():
        existing_map[(row.package_name, row.version)] = row

    for entry in entries:
        pkg = entry.get("package_name", "")
        ver = entry.get("version", "")
        if not pkg:
            continue
        existing = existing_map.get((pkg, ver))
        if existing:
            existing.last_seen_at = now
            existing.ecosystem = entry.get("ecosystem", existing.ecosystem)
            existing.license = (entry.get("license", existing.license) or "")[:500]
            existing.direct = entry.get("direct", existing.direct)
            existing.parent_packages = entry.get("parent_packages", existing.parent_packages)
            existing.depends_on = entry.get("depends_on", existing.depends_on)
        else:
            new_entry = SBOMEntry(
                application_id=app_id,
                package_name=pkg,
                version=ver,
                ecosystem=entry.get("ecosystem", ""),
                license=(entry.get("license", "") or "")[:500],
                direct=entry.get("direct", True),
                parent_packages=entry.get("parent_packages", []),
                depends_on=entry.get("depends_on", []),
                last_seen_at=now,
            )
            db.add(new_entry)
            # Register in the map so duplicates within the same batch
            # (e.g. same package across multiple scanned images of one app)
            # update the pending row instead of triggering another INSERT
            # that would violate ix_sbom_app_pkg.
            existing_map[(pkg, ver)] = new_entry
    await db.flush()
    # Remove stale entries: packages not seen in this scan are no longer
    # present in the app's dependency tree. Delete them so the SBOM stays
    # accurate and doesn't accumulate ghost packages over time.
    from sqlalchemy import delete as sa_delete
    stale = await db.execute(
        sa_delete(SBOMEntry).where(
            SBOMEntry.application_id == app_id,
            SBOMEntry.last_seen_at < now,
        )
    )
    if stale.rowcount:
        logger.info("SBOM cleanup: removed %d stale package(s) for app %s", stale.rowcount, app_id)
    await db.flush()


async def _tick() -> None:
    try:
        async with async_session() as db:
            now = datetime.now(timezone.utc)
            # Pull all enabled apps whose last scan is older than the tick
            # window, then keep the ones that have something scannable:
            # either a repo URL (for trivy_fs / gitleaks / semgrep) or at
            # least one docker image (for trivy_image). Filtering on
            # repo_url alone would silently ignore image-only apps.
            result = await db.execute(
                select(Application).where(
                    Application.enabled == True,
                    or_(
                        Application.last_scan_at == None,
                        Application.last_scan_at < now - timedelta(hours=1),
                    )
                ).order_by(Application.last_scan_at.asc().nullsfirst())
            )
            apps = [
                a for a in result.scalars().all()
                if (a.repo_url or "") or (a.docker_images or [])
            ][:MAX_PER_TICK]

            # Collect app IDs that already have active scan jobs
            active_app_ids = set()
            if apps:
                active_q = await db.execute(
                    select(ScanJob.application_id).where(
                        ScanJob.status.in_(["running", "pending"]),
                    ).distinct()
                )
                active_app_ids = {row[0] for row in active_q}

        for app in apps:
            if app.id in active_app_ids:
                continue
            freq = timedelta(hours=app.scan_frequency_hours or 24)
            if app.last_scan_at and (now - app.last_scan_at) < freq:
                continue
            logger.info("Scheduling scan for %s", app.name)
            asyncio.create_task(_scan_application(app.id))
    except Exception as e:
        logger.error("Scheduler tick error: %s", e)


PURGE_INTERVAL = timedelta(hours=24)
_last_purge: datetime | None = None


async def _purge() -> None:
    """Delete old data: fixed findings, old scan jobs, old audit logs."""
    global _last_purge
    now = datetime.now(timezone.utc)
    if _last_purge and (now - _last_purge) < PURGE_INTERVAL:
        return
    _last_purge = now
    try:
        from sqlalchemy import delete as sa_delete
        from src.models import AuditLog, AppSettings
        async with async_session() as db:
            # 1. Fixed findings — delete immediately
            #    First nullify measure FK so measures are preserved.
            from src.models import Measure
            from sqlalchemy import update as sa_update
            fixed_ids_q = await db.execute(
                select(Finding.id).where(Finding.status == "fixed")
            )
            fixed_ids = [row[0] for row in fixed_ids_q]
            if fixed_ids:
                await db.execute(
                    sa_update(Measure).where(
                        Measure.finding_id.in_(fixed_ids)
                    ).values(finding_id=None)
                )
            r1 = await db.execute(
                sa_delete(Finding).where(Finding.status == "fixed")
            )
            # 2. Scan jobs older than 30 days (completed or failed only)
            r2 = await db.execute(
                sa_delete(ScanJob).where(
                    ScanJob.status.in_(["completed", "failed"]),
                    ScanJob.created_at < now - timedelta(days=30),
                )
            )
            # 3. Audit logs — retention configurable (default 365 days)
            setting = await db.execute(
                select(AppSettings).where(AppSettings.key == "audit_retention_days")
            )
            row = setting.scalar_one_or_none()
            retention_days = int(row.value) if row and row.value.isdigit() else 365
            r3 = await db.execute(
                sa_delete(AuditLog).where(
                    AuditLog.logged_at < now - timedelta(days=retention_days),
                )
            )
            await db.commit()
            if r1.rowcount or r2.rowcount or r3.rowcount:
                logger.info("Purge: %d fixed finding(s), %d old scan job(s), "
                            "%d old audit log(s) deleted",
                            r1.rowcount, r2.rowcount, r3.rowcount)
    except Exception as e:
        logger.error("Purge error: %s", e)


async def _reset_stale_jobs(
    reason: str,
    only_orphan: bool = True,
    created_before: datetime | None = None,
) -> int:
    """Mark zombie scan jobs as ``failed`` so they stop blocking new scans.

    A ScanJob can be left in ``running``/``pending`` forever if the
    worker process was killed (OOM, container restart, asyncio task
    cancellation) — none of those paths hit the ``except`` block in
    ``_run_single_scanner``. The concurrency check in ``_do_scan``
    then refuses to start any new scan because it sees a "running"
    job, blocking the app until the row is manually fixed.

    Call sites:
      * scheduler boot — ``only_orphan=False`` + ``created_before=
        _SCHEDULER_BOOT_TIME``. Wipes every running/pending row created
        before the scheduler came up (those are zombies from the
        previous process), but leaves alone any row legitimately
        created by a user trigger during the INITIAL_DELAY warmup
        window.
      * every tick — ``only_orphan=True``. Only jobs whose
        ``started_at`` is older than ``SCAN_TIMEOUT +
        STALE_JOB_BUFFER_SECONDS`` are wiped (in-process hangs,
        runaway scanners that exceed the subprocess timeout).

    Returns the number of rows updated for logging.
    """
    from sqlalchemy import update as sa_update
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=SCAN_TIMEOUT + STALE_JOB_BUFFER_SECONDS)
    async with async_session() as db:
        stmt = sa_update(ScanJob).values(
            status="failed",
            completed_at=now,
            error=reason[:2000],
        )
        clauses = [ScanJob.status.in_(["running", "pending"])]
        if only_orphan:
            clauses.append(ScanJob.started_at.is_not(None))
            clauses.append(ScanJob.started_at < cutoff)
        if created_before is not None:
            clauses.append(ScanJob.created_at < created_before)
        stmt = stmt.where(*clauses)
        result = await db.execute(stmt)
        await db.commit()
        if result.rowcount:
            from src.audit_common import log_write
            await log_write(db, None, None, "scan.auto_reset_stuck", actor="scheduler",
                            entity_type="scan_job",
                            details={"reset": result.rowcount, "reason": reason[:120]},
                            commit=True)
        return result.rowcount or 0


async def _loop() -> None:
    await asyncio.sleep(INITIAL_DELAY)
    # On startup, any row created before the scheduler came up is an
    # orphan from the previous process. Rows created AFTER boot time
    # (during the INITIAL_DELAY warmup) belong to legitimate user
    # triggers that the API accepted — leave those alone.
    try:
        n = await _reset_stale_jobs(
            reason="container restart — job orphaned by previous process",
            only_orphan=False,
            created_before=_SCHEDULER_BOOT_TIME,
        )
        if n:
            logger.warning("Boot recovery: reset %d orphan scan job(s)", n)
    except Exception as e:
        logger.error("Boot recovery failed: %s", e)

    # Clean leaked /tmp/appsec-* dirs from previous crashes before we
    # start cloning fresh repos — disk space matters for the next clone.
    try:
        removed = _cleanup_orphan_tempdirs()
        if removed:
            logger.warning("Boot recovery: removed %d orphan tempdir(s)", removed)
    except Exception as e:
        logger.error("Boot tempdir cleanup failed: %s", e)

    tick_counter = 0
    while True:
        # Sweep in-process hangs before each tick (the per-subprocess
        # timeout normally catches them, but a stuck DB call or an
        # asyncio cancellation can still leave a row dangling).
        try:
            n = await _reset_stale_jobs(
                reason=f"stale job timed out after {SCAN_TIMEOUT + STALE_JOB_BUFFER_SECONDS}s",
                only_orphan=True,
            )
            if n:
                logger.warning("Tick sweep: reset %d stale scan job(s)", n)
        except Exception as e:
            logger.error("Stale-job sweep error: %s", e)

        # Tempdir sweep every ~10 ticks (10 minutes) — frequent enough
        # to recover from sudden OOM-kill bursts, rare enough to not
        # thrash the filesystem.
        tick_counter += 1
        if tick_counter % 10 == 0:
            try:
                removed = _cleanup_orphan_tempdirs()
                if removed:
                    logger.info("Periodic sweep: removed %d orphan tempdir(s)", removed)
            except Exception as e:
                logger.error("Periodic tempdir cleanup failed: %s", e)

        await _tick()
        await _purge()
        await asyncio.sleep(TICK_SECONDS)


_scheduler_task = None

def start_scheduler() -> None:
    """Record boot time and spawn the scheduler loop.

    Boot time is captured *here* (not at module import) so the boot
    sweep only wipes rows that pre-date the scheduler starting. The
    FastAPI lifespan calls this during startup, so the timestamp
    accurately reflects "when this process began scheduling".
    """
    global _scheduler_task, _SCHEDULER_BOOT_TIME
    _SCHEDULER_BOOT_TIME = datetime.now(timezone.utc)
    _scheduler_task = asyncio.create_task(_loop())


async def trigger_scan(app_id: uuid.UUID, triggered_by: str = "manual") -> None:
    asyncio.create_task(_scan_application(app_id, force=True, triggered_by=triggered_by))
