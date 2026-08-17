"""Watch scheduler — Phase 3 feed ingestion + matching.

The scheduler runs a single asyncio task that wakes every TICK_SECONDS
and, for every feed whose ``next_due_at`` has elapsed, kicks off an
ingestion cycle. Per-source ``asyncio.Lock`` instances prevent two
overlapping ticks if a feed pull is slower than the tick period.

Each cycle:

  1. Load the feed's FeedState row (create if missing).
  2. Call ``feed.fetch_delta(since=last_success_at, cursor=last_cursor)``.
  3. Upsert each AlertCandidate as an Alert row (on conflict do update
     on title/summary/severity/cvss/epss/kev_listed/affected_json).
  4. Run the matcher against the new/updated alerts.
  5. Update FeedState (last_sync, last_success, cursor, items_*).

Failures inside a single cycle never crash the scheduler — they are
logged and recorded on the FeedState row so the operator can see the
last error via the UI/audit.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session
from src.feeds import FEEDS, AlertCandidate, FeedError, FeedAdapter
from src.feeds.osv import OSVFeed, PURL_TO_OSV_ECOSYSTEM
from src.matcher import match_alert
from src.models import Alert, FeedState, WatchTarget

logger = logging.getLogger("watch-scheduler")

TICK_SECONDS = int(os.getenv("WATCH_TICK_SECONDS", "900"))  # 15 min default

_task: asyncio.Task | None = None
_locks: dict[str, asyncio.Lock] = {}


def _lock_for(source: str) -> asyncio.Lock:
    lk = _locks.get(source)
    if lk is None:
        lk = asyncio.Lock()
        _locks[source] = lk
    return lk


async def _loop() -> None:
    logger.info("watch scheduler loop entered (tick=%ss)", TICK_SECONDS)
    # Quick boot delay so the database is fully open before the first pull.
    await asyncio.sleep(5)
    while True:
        try:
            await _tick()
        except asyncio.CancelledError:
            logger.info("watch scheduler loop cancelled")
            raise
        except Exception:  # pragma: no cover — defensive log, never raises out
            logger.exception("watch scheduler tick failed")
        await asyncio.sleep(TICK_SECONDS)


async def _tick() -> None:
    now = datetime.now(timezone.utc)
    for feed in FEEDS:
        try:
            await _ingest_one(feed, now)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("feed %s — uncaught error during tick", feed.source)
    # Phase 5: digest dispatch. Cheap if nobody's window is open right now.
    # M22: threat-digest LLM calls happen *inside* tick_digests at send
    # time (Claude with web_search), so there's no separate scorer tick
    # to run here — the old `score_pending` worker was removed.
    try:
        async with async_session() as db:
            from src.digest import tick_digests
            await tick_digests(db)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("digest tick failed")


async def _ingest_one(feed: FeedAdapter, now: datetime) -> None:
    lock = _lock_for(feed.source)
    if lock.locked():
        logger.info("feed %s already running, skipping this tick", feed.source)
        return
    async with lock:
        async with async_session() as db:
            state = await _load_or_create_state(db, feed.source)
            if not state.enabled:
                return
            if state.next_due_at and state.next_due_at > now:
                return

            # Inject runtime context for adapters that need it (OSV needs
            # the list of (ecosystem, name) pairs to query).
            if isinstance(feed, OSVFeed):
                feed.packages = await _enumerate_osv_packages(db)

            state.last_sync_at = now
            try:
                result = await feed.fetch_delta(state.last_success_at, state.last_cursor or "")
            except FeedError as e:
                state.last_error = str(e)[:5000]
                state.next_due_at = now + timedelta(seconds=feed.interval_seconds)
                await db.commit()
                logger.warning("feed %s failed: %s", feed.source, e)
                return

            items_seen = 0
            items_new = 0
            async for candidate in result.candidates:
                items_seen += 1
                created = await _upsert_alert(db, candidate)
                if created:
                    items_new += 1
                    await match_alert(db, created)
                # Commit in batches of 50 to keep transactions short and
                # let other requests progress while a big NVD window
                # drains.
                if items_seen % 50 == 0:
                    await db.commit()

            state.last_success_at = now
            state.last_cursor = result.next_cursor or ""
            state.last_error = ""
            state.items_seen = items_seen
            state.items_new = items_new
            state.next_due_at = now + timedelta(seconds=feed.interval_seconds)
            await db.commit()

            # Journal only ingest runs that brought NEW alerts.
            if items_new:
                from src.audit_common import log_write
                await log_write(db, None, None, "feed.auto_ingest", actor="scheduler",
                                entity_type="alert", target=feed.source,
                                details={"seen": items_seen, "new": items_new},
                                commit=True)

            # Post-ingest cross-source merge: KEV → tag matching NVD alerts.
            if feed.source == "kev":
                await _propagate_kev_flag(db)

            logger.info("feed %s — seen=%s new=%s next=%s",
                        feed.source, items_seen, items_new, state.next_due_at)


async def _load_or_create_state(db: AsyncSession, source: str) -> FeedState:
    state = (await db.execute(
        select(FeedState).where(FeedState.source == source)
    )).scalar_one_or_none()
    if state is None:
        state = FeedState(source=source, enabled=True, items_seen=0, items_new=0)
        db.add(state)
        await db.flush()
    return state


async def _upsert_alert(db: AsyncSession, c: AlertCandidate) -> Alert | None:
    """Insert-or-update an Alert by (source, external_id).

    Returns the row (whether new or updated) so the matcher can run
    against it. Returns ``None`` only if the row could not be
    persisted, which should never happen in practice.
    """
    existing = (await db.execute(
        select(Alert).where(Alert.source == c.source, Alert.external_id == c.external_id)
    )).scalar_one_or_none()

    if existing is None:
        row = Alert(
            id=uuid.uuid4(),
            source=c.source,
            external_id=c.external_id,
            title=c.title[:500],
            summary=c.summary or "",
            severity=c.severity or "unknown",
            cvss_score=c.cvss_score,
            cvss_vector=c.cvss_vector or "",
            epss_score=c.epss_score,
            kev_listed=c.kev_listed,
            kev_listed_at=(datetime.now(timezone.utc) if c.kev_listed else None),
            published_at=c.published_at,
            modified_at=c.modified_at,
            references_json=list(c.references or []),
            affected_json=list(c.affected or []),
            raw_json=dict(c.raw or {}),
            ingested_at=datetime.now(timezone.utc),
        )
        db.add(row)
        await db.flush()
        return row

    # Refresh mutable fields. We never overwrite ingested_at — that's
    # the moment the row was first known to us.
    existing.title = c.title[:500] or existing.title
    existing.summary = c.summary or existing.summary
    existing.severity = c.severity or existing.severity
    if c.cvss_score is not None:
        existing.cvss_score = c.cvss_score
    if c.cvss_vector:
        existing.cvss_vector = c.cvss_vector
    if c.epss_score is not None:
        existing.epss_score = c.epss_score
    if c.kev_listed and not existing.kev_listed:
        existing.kev_listed = True
        existing.kev_listed_at = datetime.now(timezone.utc)
    if c.modified_at:
        existing.modified_at = c.modified_at
    if c.references:
        existing.references_json = list(c.references)
    if c.affected:
        existing.affected_json = list(c.affected)
    if c.raw:
        existing.raw_json = dict(c.raw)
    await db.flush()
    return existing


async def _propagate_kev_flag(db: AsyncSession) -> None:
    """After a KEV pull, set ``kev_listed=true`` on every NVD alert whose
    CVE id appears in the KEV catalogue.
    """
    kev_ids = (await db.execute(
        select(Alert.external_id).where(Alert.source == "kev")
    )).scalars().all()
    if not kev_ids:
        return
    rows = (await db.execute(
        select(Alert).where(Alert.source == "nvd", Alert.external_id.in_(kev_ids))
    )).scalars().all()
    now = datetime.now(timezone.utc)
    for r in rows:
        if not r.kev_listed:
            r.kev_listed = True
            r.kev_listed_at = now
    if rows:
        await db.commit()


async def _enumerate_osv_packages(db: AsyncSession) -> list[dict[str, str]]:
    """Distinct (ecosystem, name) pairs derived from enabled PURL targets."""
    rows = (await db.execute(
        select(WatchTarget.value).where(
            WatchTarget.enabled == True,  # noqa: E712
            WatchTarget.kind == "purl",
        )
    )).scalars().all()
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in rows:
        # PURL form: pkg:<type>/<name>[@version]
        if not value or not value.startswith("pkg:"):
            continue
        rest = value[4:]
        ptype, _, after = rest.partition("/")
        if not ptype or not after:
            continue
        name = after.split("@")[0].split("?")[0].strip("/")
        if not name:
            continue
        eco = PURL_TO_OSV_ECOSYSTEM.get(ptype.lower())
        if not eco:
            continue
        key = (eco, name.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"ecosystem": eco, "name": name})
    return out


def start_scheduler() -> None:
    global _task
    if _task is not None and not _task.done():
        return
    _task = asyncio.create_task(_loop(), name="watch-scheduler")


async def trigger_now(source: str) -> dict[str, Any]:
    """One-shot fetch-then-match for a single feed (used by the admin UI)."""
    feed = next((f for f in FEEDS if f.source == source), None)
    if feed is None:
        return {"ok": False, "error": f"unknown feed: {source}"}
    now = datetime.now(timezone.utc)
    # Reset next_due_at so _ingest_one runs immediately.
    async with async_session() as db:
        state = await _load_or_create_state(db, source)
        state.next_due_at = now - timedelta(seconds=1)
        await db.commit()
    await _ingest_one(feed, now)
    return {"ok": True, "source": source}
