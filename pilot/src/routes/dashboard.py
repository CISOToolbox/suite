"""Dashboard: aggregated stats from all modules + measure summary."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("pilot.dashboard")
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import (
    KpiDefinition,
    KpiSnapshot,
    MeasureCache,
    ModuleRegistry,
    User,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
if SERVICE_TOKEN:
    try:
        SERVICE_TOKEN.encode("ascii")
    except UnicodeEncodeError as _exc:
        logger.error(
            "SERVICE_TOKEN contains non-ASCII character at position %d (%r) — "
            "HTTP headers must be ASCII. Regenerate with `openssl rand -hex 32`. "
            "Disabling inter-module auth header until fixed.",
            _exc.start, _exc.object[_exc.start:_exc.end],
        )
        SERVICE_TOKEN = ""


# ═══════════════════════════════════════════════════════════════════════
# Dashboard v2 — consolidated CISO posture cockpit.
# See shared/docs/pilot-dashboard-contract.md for the wire format.
# Each backend module exposes GET /api/internal/stats (mandatory) and
# optionally /api/internal/activity (max 10 recent events). Pilot does:
#   1. Fan out health + stats + activity calls in parallel (per module).
#   2. Compute consolidated KPIs (global posture, totals, criticals).
#   3. Merge all activity feeds + derive `upcoming` from MeasureCache.
# ═══════════════════════════════════════════════════════════════════════

# Module weights for the weighted posture_global KPI. "kpis" is the local
# Pilot KPI panel (see _compute_kpi_posture below) — given a non-trivial
# weight so the top-level Posture aligns with what the KPI panel shows.
_POSTURE_WEIGHTS = {
    "risk": 2.0,
    "compliance": 2.0,
    "vendor": 1.5,
    "surface": 1.5,
    "audit": 1.0,
    "asset": 1.0,
    "access": 1.0,
    "kpis": 2.0,
}


def _kpi_health_color(value: float, target, amber, red, direction: str) -> str:
    """Mirror of frontend `_kpiHealth` so backend posture matches the panel."""
    if direction == "higher_better":
        if red is not None and value < red:
            return "red"
        if amber is not None and value < amber:
            return "amber"
        if target is not None and value < target:
            return "amber"
        return "green"
    else:  # lower_better
        if red is not None and value > red:
            return "red"
        if amber is not None and value > amber:
            return "amber"
        if target is not None and value > target:
            return "amber"
        return "green"


async def _compute_kpi_posture(db: AsyncSession) -> float | None:
    """Score the local Pilot KPI panel on the same 0-100 scale modules use.

    Score = (green*100 + amber*50) / (green + amber + red).
    Active KPIs without a snapshot are skipped (counted as "no data" — they
    don't drag the score down, just like the frontend overview chip).
    Returns None when no active KPI has a snapshot yet.
    """
    defs = (await db.execute(
        select(KpiDefinition).where(KpiDefinition.active.is_(True))
    )).scalars().all()
    if not defs:
        return None
    defs_by_id = {d.id: d for d in defs}

    # Latest snapshot per active KPI in ONE query instead of a SELECT-LIMIT-1
    # per KPI (previously 1 + N queries on every dashboard GET). Ordered by
    # (kpi_id, captured_at DESC) — backed by ix_kpi_snapshot_kpi_captured — so
    # the first row seen per kpi_id is its latest. Dedup in Python keeps this
    # portable (no Postgres-only DISTINCT ON).
    rows = (await db.execute(
        select(KpiSnapshot)
        .where(KpiSnapshot.kpi_id.in_(list(defs_by_id.keys())))
        .order_by(KpiSnapshot.kpi_id, KpiSnapshot.captured_at.desc())
    )).scalars().all()

    seen: set = set()
    green = amber = red = 0
    for latest in rows:
        if latest.kpi_id in seen:
            continue
        seen.add(latest.kpi_id)
        d = defs_by_id.get(latest.kpi_id)
        if d is None:
            continue
        color = _kpi_health_color(
            float(latest.value),
            d.target,
            d.threshold_amber,
            d.threshold_red,
            d.direction,
        )
        if color == "green":
            green += 1
        elif color == "amber":
            amber += 1
        else:
            red += 1

    denom = green + amber + red
    if denom == 0:
        return None
    return (green * 100.0 + amber * 50.0) / denom


def _posture_label(score):
    if score is None:
        return ""
    if score < 40:
        return "Faible"
    if score < 60:
        return "Modéré"
    if score < 80:
        return "Bon"
    return "Excellent"


_CRIT_LABELS = ("Critique", "Élevé", "Critical", "High")


def _count_critical(module_id: str, stats: dict) -> int:
    """Count 'critical' items for a module from its stats envelope.

    Prefers the semantic top-level ``criticals`` field — modules emit it
    straight from their data, so a cosmetic relabel or i18n change can no
    longer zero this top-level KPI. Falls back to the legacy breakdown-label
    heuristic only for a module that predates the field, so a mixed-version
    deployment during a rollout doesn't lose the count.
    """
    if not isinstance(stats, dict):
        return 0
    semantic = stats.get("criticals")
    if isinstance(semantic, int) and not isinstance(semantic, bool):
        return semantic
    # Legacy fallback (localization-coupled) — see the semantic field above.
    bd = stats.get("breakdown") or {}
    data = bd.get("data") or {}
    btype = bd.get("type")
    if module_id in ("risk", "vendor") and btype == "donut":
        return sum(int(s.get("value") or 0) for s in (data.get("segments") or [])
                   if s.get("label") in _CRIT_LABELS)
    if module_id == "surface" and btype == "bar":
        return sum(int(b.get("value") or 0) for b in (data.get("buckets") or [])
                   if b.get("label") in _CRIT_LABELS)
    return 0


async def _fetch_module(client: httpx.AsyncClient, m, headers: dict) -> dict:
    """Fetch health + stats + activity for one module. Returns a dict
    ready to append to `modules[]` plus the activity events."""
    stats = None
    activity = []
    if not m.internal_url:
        return {
            "card": {"id": m.id, "name": m.name, "url": m.external_url,
                     "status": "external", "stats": None},
            "activity": [],
        }
    health_url = m.internal_url.rstrip("/") + "/api/health"
    stats_url = m.internal_url.rstrip("/") + "/api/internal/stats"
    activity_url = m.internal_url.rstrip("/") + "/api/internal/activity"
    status = "unreachable"
    try:
        resp = await client.get(health_url, headers=headers)
        if resp.status_code == 200:
            status = "active"
            # stats + activity are independent — fetch concurrently instead of
            # serially, halving this module's contribution to dashboard latency.
            sr, ar = await asyncio.gather(
                client.get(stats_url, headers=headers),
                client.get(activity_url, headers=headers),
                return_exceptions=True,
            )
            if isinstance(sr, Exception):
                logger.warning("module %s stats fetch failed: %s", m.id, sr)
            elif sr.is_success:
                stats = sr.json()
            if not isinstance(ar, Exception) and ar.is_success:
                try:
                    body = ar.json()
                    if isinstance(body, list):
                        activity = body
                except Exception:
                    logger.debug("module %s activity not parseable", m.id)
        else:
            status = "error"
            logger.warning("module %s health returned %s", m.id, resp.status_code)
    except Exception as e:
        logger.warning("module %s unreachable: %s", m.id, e)
    # Only dirty the row when the status actually changed — module_registry is
    # otherwise re-written (and dead-tupled) on every 30s poll. last_health has
    # no reader, so refreshing it only on transition is observationally free.
    if m.status != status:
        m.status = status
        m.last_health = datetime.now(timezone.utc)
    return {
        "card": {
            "id": m.id,
            "name": m.name,
            "url": m.external_url,
            "status": status,
            "stats": stats,
        },
        "activity": activity,
    }


# Per-module fan-out cache: module_id -> (fetch_result, monotonic_ts). The
# health+stats+activity fetch of each module is the expensive part of the
# dashboard and is identical for every user/tab polling within the window, so
# cache it briefly. TTL < the 30s frontend poll keeps the data near-live while
# collapsing concurrent/overlapping polls (multi-user, multi-tab) to ONE fan-out
# per module per window. Multi-worker → per-worker cache (still collapses each
# worker's polls). Tunable via DASHBOARD_CACHE_TTL.
_MODULE_CACHE: dict[str, tuple[dict, float]] = {}
_MODULE_TTL = float(os.getenv("DASHBOARD_CACHE_TTL", "20"))


async def _collect_cards(wanted, headers, db) -> tuple[list[dict], list[dict]]:
    """Fan out to `wanted` modules through the per-module TTL cache and return
    (module_cards, all_activity). Fetches only modules whose cache is stale;
    the rest reuse the last fan-out. On a full cache hit no HTTP / DB write
    happens. Persists any status transitions from the fetches."""
    now = time.monotonic()
    to_fetch = [m for m in wanted if now - _MODULE_CACHE.get(m.id, (None, 0.0))[1] >= _MODULE_TTL]
    if to_fetch:
        async with httpx.AsyncClient(timeout=5.0) as client:
            results = await asyncio.gather(
                *[_fetch_module(client, m, headers) for m in to_fetch],
                return_exceptions=True,
            )
        for m, r in zip(to_fetch, results):
            if isinstance(r, Exception):
                logger.warning("module %s fetch error: %s", m.id, r)
                continue
            _MODULE_CACHE[m.id] = (r, now)
        await db.commit()

    cards: list[dict] = []
    activity: list[dict] = []
    for m in wanted:
        entry = _MODULE_CACHE.get(m.id)
        if entry is None:
            continue
        cards.append(entry[0]["card"])
        activity.extend(entry[0]["activity"] or [])
    return cards, activity


async def _backup_health() -> dict | None:
    """Backup freshness + last restore-test from the agent (FEAT-30 ph.3).
    Best-effort: a missing/down agent yields None, never a dashboard error."""
    import os as _os
    token = _os.getenv("BACKUP_AGENT_TOKEN", "")
    url = _os.getenv("BACKUP_AGENT_URL", "http://backup-agent:9090")
    if not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(url.rstrip("/") + "/health",
                                    headers={"X-Agent-Token": token})
            if resp.is_success:
                return resp.json()
    except httpx.HTTPError:
        pass
    return None


@router.get("")
async def get_dashboard(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ModuleRegistry))
    modules = result.scalars().all()
    user_modules = (user.modules if user else None) or [m.id for m in modules]
    if user and user.role == "admin":
        user_modules = [m.id for m in modules]

    headers = {"X-Service-Token": SERVICE_TOKEN} if SERVICE_TOKEN else {}
    wanted = [m for m in modules if m.id in user_modules]
    module_cards, all_activity = await _collect_cards(wanted, headers, db)

    # ── KPI aggregation ──
    posture_total = 0.0
    posture_weight = 0.0
    measures_total = 0
    measures_overdue = 0
    proofs_expired_10d = 0
    # FEAT-08 — cross-module evidence expiry from EvidenceCache.
    from src.models import EvidenceCache as _EvC
    _ev_rows = (await db.execute(select(_EvC))).scalars().all()
    evidences_summary = {
        "total": len(_ev_rows),
        "expired": sum(1 for e in _ev_rows if (e.data or {}).get("status") == "expiree"),
        "expiring_soon": sum(1 for e in _ev_rows if (e.data or {}).get("status") == "bientot"),
    }
    critical_breakdown: dict[str, int] = {}

    for card in module_cards:
        stats = card.get("stats") or {}
        # Global posture (weighted mean, null scores skipped)
        posture = (stats.get("posture") or {}).get("score")
        if posture is not None:
            w = _POSTURE_WEIGHTS.get(card["id"], 1.0)
            posture_total += posture * w
            posture_weight += w
        # Totals from measures block
        m = stats.get("measures") or {}
        measures_total += int(m.get("total") or 0)
        measures_overdue += int(m.get("overdue") or 0)
        proofs_expired_10d += int(m.get("proofs_expired_10d") or 0)
        # Criticals
        c = _count_critical(card["id"], stats)
        if c > 0:
            critical_breakdown[card["id"]] = c

    # Fold the local KPI panel into the weighted mean so the top-level
    # Posture aligns with what the Indicateurs view shows.
    kpi_posture = await _compute_kpi_posture(db)
    if kpi_posture is not None:
        w = _POSTURE_WEIGHTS.get("kpis", 1.0)
        posture_total += kpi_posture * w
        posture_weight += w

    posture_global = round(posture_total / posture_weight) if posture_weight > 0 else None

    # ── Upcoming deadlines from MeasureCache (next 5) ──
    # Only fetch the rows we actually need: non-completed with a future due_date
    from datetime import date
    today_str = date.today().isoformat()
    upcoming_result = await db.execute(
        select(MeasureCache)
        .where(MeasureCache.data["due_date"].astext >= today_str)
        .where(MeasureCache.data["status"].astext.notin_(
            ["completed", "termine", "Terminé",
             # Une mesure abandonnée n'a plus d'échéance à tenir.
             "cancelled", "annule", "Annulé", "abandonne"]))
        .order_by(MeasureCache.data["due_date"].astext.asc())
        .limit(5)
    )
    upcoming = []
    for mc in upcoming_result.scalars().all():
        d = mc.data or {}
        due = d.get("due_date", "")
        try:
            days_left = (date.fromisoformat(due) - date.today()).days
        except Exception:
            days_left = None
        upcoming.append({
            "date": due,
            "module": mc.module,
            "label": (d.get("title") or d.get("mesure") or "Mesure")[:80],
            "url": f"/{mc.module}/",
            "days_left": days_left,
        })
    # Count completed measures (rough 30d indicator) via SQL
    measures_done_30d = (await db.scalar(
        select(func.count()).select_from(MeasureCache)
        .where(MeasureCache.data["status"].astext.in_(["completed", "termine", "Terminé"]))
    )) or 0

    # ── Activity feed: sort + cap to 10 ──
    def _sort_key(ev):
        return ev.get("date", "")
    all_activity.sort(key=_sort_key, reverse=True)
    activity = all_activity[:10]

    kpis = {
        "posture_global": posture_global,
        "posture_label": _posture_label(posture_global),
        "posture_kpi_panel": round(kpi_posture) if kpi_posture is not None else None,
        "measures_total": measures_total,
        "measures_overdue": measures_overdue,
        "measures_done_last_30d": measures_done_30d,
        "proofs_expired_10d": proofs_expired_10d,
        # FEAT-08 — transverse evidence summary from the consolidated cache
        # (see pilot-dashboard-contract.md §kpis.evidences).
        "evidences": evidences_summary,
        "critical_count": sum(critical_breakdown.values()),
        "critical_breakdown": critical_breakdown,
    }

    # ── Backup health (FEAT-30 phase 3) ──
    backup_health = await _backup_health()
    backups_summary = None
    if backup_health:
        stanzas = backup_health.get("stanzas") or {}
        stale = [m for m, s in stanzas.items() if s.get("stale")]
        rtest = backup_health.get("restore_test") or {}
        failed_tests = [r.get("module") for r in (rtest.get("results") or [])
                        if not r.get("ok")]
        backups_summary = {
            "stanzas_total": len(stanzas),
            "stanzas_stale": stale,
            "restore_test_at": rtest.get("updated_at"),
            "restore_test_failed": failed_tests,
        }

    return {
        "modules": module_cards,
        "kpis": kpis,
        "activity": activity,
        "upcoming": upcoming,
        "backups": backups_summary,
        # Legacy key for frontends that still read measures_summary
        "measures_summary": {
            "total": measures_total,
            "overdue": measures_overdue,
            "by_status": {},
            "by_module": {},
        },
    }
