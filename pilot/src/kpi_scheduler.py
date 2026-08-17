"""Auto-compute scheduler for ``source_type='auto'`` KPIs.

On each pass, every active auto KPI is resolved:

* ``source_module`` is a real module → fetch the module's
  ``/api/internal/stats`` once per pass; extract ``source_metric``
  using a small JSONPath subset (``$.posture.score``).
* ``source_module='pilot'`` → resolve locally against Pilot's own
  ``MeasureCache`` for a handful of well-known metric names
  (``pilot:measures.critical_closed_30d``, ``pilot:findings.p1_open``…).

Resolved values flow through ``routes/kpis._ingest`` so every snapshot
goes through the SAME idempotency-guarded write path as plugin /
manual ingests. ``captured_at`` is bucketed to the start of the UTC
day so the history shows one row per day per KPI — a finer cadence
just generates noise on a slow-moving posture indicator. Multiple
passes inside the same day refresh the row's value (last-pass-wins
for ``source='auto'``) rather than creating duplicates.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.connectors import graph as graph_connector
from src.connectors import aws as aws_connector
from src.database import async_session
from src.models import KpiDefinition, MeasureCache, ModuleRegistry
from src.routes.kpis import _ingest

logger = logging.getLogger("pilot.kpi.scheduler")

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
_INTERVAL_SECONDS = int(os.getenv("KPI_AUTO_INTERVAL_SECONDS", "86400"))
_INITIAL_DELAY = int(os.getenv("KPI_AUTO_INITIAL_DELAY", "60"))

# Status strings considered "completed" across modules (French + English).
_COMPLETED_STATUSES = ("completed", "done", "termine", "Terminé", "terminé", "closed")

# Severity / criticality strings that count as "critical" across modules.
_CRITICAL_SEVERITIES = ("critical", "critique", "high", "haute", "p1", "P1")

_compute_task: Optional[asyncio.Task] = None


# --------------------------------------------------------------------------- #
# Resolvers                                                                    #
# --------------------------------------------------------------------------- #


def _resolve_jsonpath(stats: dict[str, Any], metric: str) -> Optional[float]:
    """Tiny subset of JSONPath: ``$.a.b.c`` → ``stats['a']['b']['c']``.
    Returns None on missing / non-numeric value."""
    if not metric.startswith("$."):
        return None
    cur: Any = stats
    for part in metric[2:].split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if isinstance(cur, (int, float)):
        return float(cur)
    return None


async def _resolve_pilot_metric(name: str, db: AsyncSession) -> Optional[float]:
    """Resolve pilot-local synthetic metrics.

    Supported names (matches the catalogue):
      * ``pilot:measures.critical_closed_30d`` — count of critical-severity
        measures whose status moved to a completed value in the last 30 days.
      * ``pilot:findings.p1_open`` — count of priority-1 findings still open
        across surface/appsec measure caches.

    Anything else returns None (and is skipped without crashing the pass)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    if name == "pilot:measures.critical_closed_30d":
        q = (
            select(func.count())
            .select_from(MeasureCache)
            .where(MeasureCache.synced_at >= cutoff)
            .where(MeasureCache.data["status"].astext.in_(_COMPLETED_STATUSES))
            .where(
                MeasureCache.data["severity"].astext.in_(_CRITICAL_SEVERITIES)
                | MeasureCache.data["criticality"].astext.in_(_CRITICAL_SEVERITIES)
                | MeasureCache.data["priority"].astext.in_(_CRITICAL_SEVERITIES)
            )
        )
        count = await db.scalar(q)
        return float(count or 0)

    if name == "pilot:findings.p1_open":
        q = (
            select(func.count())
            .select_from(MeasureCache)
            .where(MeasureCache.module.in_(("surface", "appsec")))
            .where(MeasureCache.data["status"].astext.notin_(_COMPLETED_STATUSES))
            .where(
                MeasureCache.data["severity"].astext.in_(_CRITICAL_SEVERITIES)
                | MeasureCache.data["priority"].astext.in_(_CRITICAL_SEVERITIES)
            )
        )
        count = await db.scalar(q)
        return float(count or 0)

    return None


# --------------------------------------------------------------------------- #
# Compute pass                                                                 #
# --------------------------------------------------------------------------- #


def _bucket_to_day(now: datetime) -> datetime:
    """Round to the start of the UTC day so multiple passes in the same
    day land on the same idempotency key (one row per KPI per day)."""
    return now.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)


async def _fetch_module_stats(
    client: httpx.AsyncClient, modules: dict[str, ModuleRegistry]
) -> dict[str, dict[str, Any]]:
    """Pull /api/internal/stats from every reachable module, in parallel."""
    headers = {"X-Service-Token": SERVICE_TOKEN} if SERVICE_TOKEN else {}
    out: dict[str, dict[str, Any]] = {}

    async def _one(mod_id: str, m: ModuleRegistry) -> tuple[str, Optional[dict]]:
        if not m.internal_url:
            return mod_id, None
        try:
            r = await client.get(
                m.internal_url.rstrip("/") + "/api/internal/stats",
                headers=headers,
            )
            if r.is_success:
                body = r.json()
                if isinstance(body, dict):
                    return mod_id, body
        except Exception as e:
            logger.warning("KPI auto: stats fetch %s failed: %s", mod_id, e)
        return mod_id, None

    results = await asyncio.gather(*[_one(k, v) for k, v in modules.items()])
    for mid, stats in results:
        if stats is not None:
            out[mid] = stats
    return out


async def compute_auto_kpis_once(db: AsyncSession) -> dict[str, int]:
    """Single compute pass. Used both by the loop and the admin trigger.

    Returns a tally for logging / API response."""
    bucket = _bucket_to_day(datetime.now(timezone.utc))

    auto_kpis = (
        await db.execute(
            select(KpiDefinition).where(
                KpiDefinition.source_type == "auto",
                KpiDefinition.active.is_(True),
            )
        )
    ).scalars().all()

    if not auto_kpis:
        return {"computed": 0, "skipped": 0, "errors": 0}

    # Collect the set of remote modules we'll need stats for. ``pilot``
    # is resolved locally; ``connector`` is resolved via the connectors
    # package — neither hits /api/internal/stats.
    remote_modules = {
        k.source_module
        for k in auto_kpis
        if k.source_module and k.source_module not in ("pilot", "connector")
    }
    stats_by_module: dict[str, dict[str, Any]] = {}
    if remote_modules:
        regs = (
            await db.execute(
                select(ModuleRegistry).where(ModuleRegistry.id.in_(remote_modules))
            )
        ).scalars().all()
        regs_by_id = {r.id: r for r in regs}
        # Only fetch modules we actually have a registry entry for.
        async with httpx.AsyncClient(timeout=5.0) as client:
            stats_by_module = await _fetch_module_stats(client, regs_by_id)

    computed = 0
    skipped = 0
    errors = 0

    for kpi in auto_kpis:
        try:
            metric = kpi.source_metric or ""
            value: Optional[float] = None

            if metric.startswith("pilot:"):
                value = await _resolve_pilot_metric(metric, db)
            elif kpi.source_module == "connector":
                if metric.startswith("aws_"):
                    value = await aws_connector.resolve_metric(metric, db)
                else:
                    value = await graph_connector.resolve_metric(metric, db)
            elif metric.startswith("$.") and kpi.source_module:
                stats = stats_by_module.get(kpi.source_module)
                if stats is not None:
                    value = _resolve_jsonpath(stats, metric)

            if value is None:
                skipped += 1
                logger.debug(
                    "KPI auto: skip %s (no value for %r)", kpi.code, metric
                )
                continue

            await _ingest(
                db,
                code=kpi.code,
                value=value,
                captured_at=bucket,
                source="auto",
                note=None,
                raw_payload={
                    "metric": metric,
                    "module": kpi.source_module,
                },
            )
            computed += 1
        except Exception as e:
            errors += 1
            logger.warning("KPI auto: ingest %s failed: %s", kpi.code, e)

    logger.info(
        "KPI auto pass done: computed=%d skipped=%d errors=%d bucket=%s",
        computed,
        skipped,
        errors,
        bucket.isoformat(),
    )
    return {"computed": computed, "skipped": skipped, "errors": errors}


# --------------------------------------------------------------------------- #
# Background loop                                                              #
# --------------------------------------------------------------------------- #


async def _compute_loop() -> None:
    # Let the rest of the app finish booting (modules registry, healthchecks)
    # before hammering everyone's /api/internal/stats.
    await asyncio.sleep(_INITIAL_DELAY)
    while True:
        try:
            async with async_session() as db:
                tally = await compute_auto_kpis_once(db)
                # Journal only passes that wrote snapshots.
                if (tally or {}).get("computed"):
                    from src.audit import log_write
                    await log_write(db, None, None, "kpi.auto_compute", actor="scheduler",
                                    entity_type="kpi", details=tally, commit=True)
        except Exception:  # pragma: no cover — must not kill the loop
            logger.exception("KPI auto pass crashed")
        # FEAT-18: periodic Proofpoint PSAT awareness sync (self-skips when the
        # connector is not configured / demo disabled). Lazy import to avoid any
        # import cycle. Failures here must not kill the KPI loop.
        try:
            from src.connectors import proofpoint_psat as _psat
            async with async_session() as db:
                await _psat.run_sync(db)
        except Exception:  # pragma: no cover
            logger.exception("PSAT awareness sync crashed")
        await asyncio.sleep(_INTERVAL_SECONDS)


def start_kpi_scheduler() -> None:
    global _compute_task
    if _compute_task is None:
        _compute_task = asyncio.create_task(_compute_loop())
