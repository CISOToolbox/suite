from __future__ import annotations

import asyncio
import logging
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import datetime, timezone

from src.database import get_db
from src.settings_crypto import encrypt_setting_or_plain
from src.models import (
    AppSettings,
    Finding,
    Measure,
    MonitoredAsset,
    ScanExclusion,
    ScanJob,
    User,
)

logger = logging.getLogger("surface.internal")

router = APIRouter(prefix="/api", tags=["internal"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
MODULE_NAME = os.getenv("MODULE_NAME", "surface")
PILOT_URL = os.getenv("PILOT_URL", "")

# Placeholder for custom LLM config (consumed by ai.py). Empty by default.
_custom_llm: dict = {}


def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    if not token or not secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


def _normalize_status(s: str) -> str:
    mapping = {
        "termine": "completed", "completed": "completed",
        "en_cours": "in_progress", "in_progress": "in_progress",
        "a_faire": "planned", "planifie": "planned", "planned": "planned",
    }
    return mapping.get(s, s)


def _denormalize_status(s: str) -> str:
    mapping = {
        "completed": "termine",
        "in_progress": "en_cours",
        "planned": "a_faire",
    }
    return mapping.get(s, s)


@router.get("/internal/stats")
async def internal_stats(request: Request, db: AsyncSession = Depends(get_db)):
    """Stats v2 envelope — see shared/docs/pilot-dashboard-contract.md"""
    _check_service_token(request)
    from datetime import date as _date

    total_findings = await db.scalar(select(func.count()).select_from(Finding)) or 0
    open_filter = Finding.status.in_(["new", "to_fix", "in_progress"])

    crit = await db.scalar(
        select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "critical")
    ) or 0
    high = await db.scalar(
        select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "high")
    ) or 0
    med = await db.scalar(
        select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "medium")
    ) or 0
    low = await db.scalar(
        select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "low")
    ) or 0
    new_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "new")) or 0
    fp_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "false_positive")) or 0
    tofix_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "to_fix")) or 0

    measure_rows = (await db.execute(
        select(Measure.statut, func.count()).group_by(Measure.statut)
    )).all()
    measure_counts = {s: c for s, c in measure_rows}
    total_measures = sum(measure_counts.values())
    completed = measure_counts.get("termine", 0) + measure_counts.get("completed", 0)
    in_progress = measure_counts.get("en_cours", 0) + measure_counts.get("in_progress", 0)
    planned = total_measures - completed - in_progress

    today = _date.today().isoformat()
    overdue = (await db.scalar(
        select(func.count()).select_from(Measure)
        .where(Measure.echeance < today, Measure.echeance != "", Measure.echeance.isnot(None))
        .where(Measure.statut.notin_(["termine", "completed"]))
    )) or 0

    progress_pct = round(completed / total_measures * 100) if total_measures else 0

    penalty = crit * 10 + high * 3 + med * 1
    posture_score = max(0, min(100, 100 - penalty))

    buckets = [
        {"label": "Critical", "value": crit, "color": "redMax"},
        {"label": "High",     "value": high, "color": "red"},
        {"label": "Medium",   "value": med,  "color": "orange"},
        {"label": "Low",      "value": low,  "color": "yellow"},
    ]
    scale = max((b["value"] for b in buckets), default=1) or 1

    # Top 3 hosts with the most critical/high open findings
    from sqlalchemy import case as sa_case
    host_sev = (
        select(
            Finding.target,
            func.count().label("cnt"),
            func.sum(sa_case(
                (Finding.severity == "critical", 10),
                (Finding.severity == "high", 3),
                else_=1,
            )).label("weight"),
        )
        .where(open_filter, Finding.target.isnot(None), Finding.target != "")
        .group_by(Finding.target)
        .order_by(func.sum(sa_case(
            (Finding.severity == "critical", 10),
            (Finding.severity == "high", 3),
            else_=1,
        )).desc())
        .limit(3)
    )
    host_result = await db.execute(host_sev)
    top_items = [{
        "id": row.target,
        "label": (row.target or "")[:80],
        "severity": "critical" if row.weight >= 10 else "high",
        "url": "/surface/",
        "meta": f"{row.cnt} finding(s)",
    } for row in host_result.all()]

    alerts = []
    if crit > 0:
        alerts.append({
            "level": "critical",
            "text": f"{crit} finding(s) critique(s) ouvert(s)",
            "url": "/surface/",
        })
    if overdue > 0:
        alerts.append({
            "level": "warning",
            "text": f"{overdue} mesure(s) en retard",
            "url": "/surface/",
        })

    return {
        "entity_count": total_findings,
        "entity_label": "Findings",
        # Semantic critical count so Pilot doesn't parse localized breakdown
        # labels — open findings of critical or high severity.
        "criticals": crit + high,
        "measures": {
            "total": total_measures,
            "completed": completed,
            "in_progress": in_progress,
            "planned": planned,
            "overdue": overdue,
            "progress_pct": progress_pct,
        },
        "posture": {
            "score": posture_score,
            "score_label": _posture_label(posture_score),
        },
        "breakdown": {
            "type": "bar",
            "data": {"buckets": buckets, "scale": scale, "unit": ""},
        },
        "top_items": top_items,
        "alerts": alerts,
        # Legacy
        "total_findings": total_findings,
        "new_findings": new_findings,
        "false_positive_findings": fp_findings,
        "to_fix_findings": tofix_findings,
        "critical_findings": crit,
        "high_findings": high,
        "total_measures": total_measures,
        "measures_progress": progress_pct,
    }


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


@router.get("/internal/activity")
async def internal_activity(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    events = []
    recent = await db.execute(
        select(Finding).order_by(Finding.created_at.desc()).limit(10)
    )
    for f in recent.scalars().all():
        ts = (f.created_at or datetime.now(timezone.utc)).isoformat() if f.created_at else datetime.now(timezone.utc).isoformat()
        events.append({
            "date": ts,
            "module": "surface",
            "type": "finding_created",
            "label": f"Nouveau finding {f.severity or ''} — {(f.title or f.target or '')[:50]}",
            "url": "/surface/",
        })
    return events[:10]


@router.get("/internal/measures")
async def internal_measures(request: Request, db: AsyncSession = Depends(get_db)):
    """Return measures (only) — findings stay local until triaged to to_fix."""
    _check_service_token(request)
    result = await db.execute(
        select(Measure, Finding).join(Finding, Measure.finding_id == Finding.id).order_by(Measure.sort_order)
    )
    out = []
    for m, f in result.all():
        out.append({
            "source_id": m.id,
            "entity_id": str(f.id),
            "entity_name": f.target or f.title,
            "title": m.title,
            "description": m.description or "",
            "status": _normalize_status(m.statut),
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
            "progress_log": m.progress_log or [],
            "type": f.type,
            "severity": f.severity,
            "source_module": MODULE_NAME,
        })
    return out


def _measure_to_pilot_payload(m: Measure, f: Finding | None = None) -> dict:
    return {
        "source_id": m.id,
        "entity_id": str(m.finding_id) if m.finding_id else "",
        "entity_name": (f.target or f.title or "") if f else "",
        "title": m.title or "",
        "description": m.description or "",
        "status": _normalize_status(m.statut or ""),
        "assignee": m.responsable or "",
        "due_date": m.echeance or "",
        "type": (f.type or "") if f else "",
        "severity": (f.severity or "") if f else "",
    }


@router.patch("/internal/measures/{source_id}")
async def patch_measure(source_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    body = await request.json()
    m = await db.get(Measure, source_id)
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    if "title" in body:
        m.title = body["title"]
    if "description" in body:
        m.description = body["description"]
    if "status" in body:
        mapped = _denormalize_status(body["status"])
        if mapped not in ("a_faire", "en_cours", "termine"):
            raise HTTPException(status_code=400, detail=f"Invalid status: {body['status']}")
        m.statut = mapped
    if "assignee" in body:
        m.responsable = body["assignee"]
    if "due_date" in body:
        m.echeance = body["due_date"]
    if "progress_log" in body:
        m.progress_log = body["progress_log"]
    # Pilot write-back is a business write — journaled (FEAT-30 review).
    from src.audit_common import log_write
    await log_write(db, None, request, "measure.writeback_update", actor="pilot",
                    entity_type="measure", entity_id=str(source_id))
    await db.commit()
    f = await db.get(Finding, m.finding_id) if m.finding_id else None
    from src.pilot_notify import notify_pilot_measure
    asyncio.ensure_future(notify_pilot_measure(_measure_to_pilot_payload(m, f)))
    return {"ok": True}


@router.delete("/internal/measures/{source_id}", status_code=204)
async def delete_measure_internal(source_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Delete a measure via Pilot write-back."""
    _check_service_token(request)
    m = await db.get(Measure, source_id)
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    await db.delete(m)
    # Pilot write-back is a business write — journaled (FEAT-30 review).
    from src.audit_common import log_write
    await log_write(db, None, request, "measure.writeback_delete", actor="pilot",
                    entity_type="measure", entity_id=str(source_id))
    await db.commit()


# ═══════════════════════════════════════════════════════════════
# BACKUP / RESTORE — consumed by Pilot's centralized backup loop.
#
# Surface is single-tenant (no Project concept), so the centralized
# backup model that expects "list of items" collapses to a single
# logical item identified by the fixed key "surface". The export
# returns the perimeter (monitored_assets), the findings, the
# remediation measures, the recent scan-job history and the AppSettings
# rows. Users, audit_log entries and the ai_managed_by_pilot runtime
# state are intentionally NOT included:
#   - users come from Pilot provisioning (sync-user above)
#   - audit_log is intentionally per-instance and immutable
#   - the AI runtime is pushed by Pilot, not user-owned data
# ═══════════════════════════════════════════════════════════════

_INSTANCE_ID = "surface"
_SCAN_JOB_BACKUP_LIMIT = 500  # keep the last N scan jobs in the snapshot


def _row_dict(obj, skip=()) -> dict:
    """Serialize a single row, JSON-safe (datetimes -> isoformat).
    Timestamps ARE exported (FEAT-30): findings keep their first-seen
    date and scan_jobs keep their chronology through a restore."""
    out: dict = {}
    for col in obj.__table__.columns:
        if col.name in skip:
            continue
        v = getattr(obj, col.name)
        if isinstance(v, datetime):
            v = v.isoformat()
        elif hasattr(v, "hex") and not isinstance(v, (bytes, bytearray)):
            # UUID
            v = str(v)
        out[col.name] = v
    return out


from src.backup_common import coerce as _bk_coerce


def _coerce(model, payload: dict, dropped: dict | None = None) -> dict:
    """Type-aware coerce (ISO strings back to datetime/date) that counts
    dropped keys instead of losing them silently. See backup_common."""
    return _bk_coerce(model, payload, dropped)


@router.get("/internal/export")
async def internal_export_list(request: Request, db: AsyncSession = Depends(get_db)):
    """Return a single-item list — Surface has no project granularity."""
    _check_service_token(request)
    updated_at = datetime.now(timezone.utc).isoformat()
    return [{
        "id": _INSTANCE_ID,
        "name": "Surface instance",
        "organization": "",
        "updated_at": updated_at,
    }]


@router.get("/internal/export/{item_id}")
async def internal_export_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Full state snapshot. ``item_id`` must equal ``surface``."""
    _check_service_token(request)
    if item_id != _INSTANCE_ID:
        raise HTTPException(status_code=404, detail="Not found")

    assets = (await db.execute(select(MonitoredAsset))).scalars().all()
    findings = (await db.execute(select(Finding))).scalars().all()
    measures = (
        await db.execute(select(Measure).order_by(Measure.sort_order))
    ).scalars().all()
    scan_jobs = (
        await db.execute(
            select(ScanJob).order_by(ScanJob.created_at.desc()).limit(_SCAN_JOB_BACKUP_LIMIT)
        )
    ).scalars().all()
    # Whitelist AppSettings keys — exclude AI runtime keys pushed by
    # Pilot so a restore on a different deployment does not overwrite
    # the current Pilot configuration.
    settings_rows = (await db.execute(select(AppSettings))).scalars().all()
    safe_settings = [
        {"key": s.key, "value": s.value}
        for s in settings_rows
        if not s.key.startswith("ai_")
    ]

    exclusions = (await db.execute(select(ScanExclusion))).scalars().all()

    return {
        "id": _INSTANCE_ID,
        "name": "Surface instance",
        "organization": "",
        "data": {
            "monitored_assets": [_row_dict(a) for a in assets],
            "findings": [_row_dict(f) for f in findings],
            "measures": [_row_dict(m) for m in measures],
            "scan_jobs": [_row_dict(j) for j in scan_jobs],
            # Operator-maintained blocklist (never-scan values) — losing it
            # on a fresh-instance restore was a real operational risk
            # (FEAT-30 audit P1.9).
            "scan_exclusions": [_row_dict(e) for e in exclusions],
            "app_settings": safe_settings,
        },
    }


@router.put("/internal/restore/{item_id}")
async def internal_restore_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Overwrite the instance state with the backup payload.

    Wipes monitored_assets, findings, measures and scan_jobs, then
    re-inserts from the payload. Users / audit_log / ai_* settings are
    preserved. Measures are NOT re-pushed to Pilot here — the restore
    is assumed to happen on the same Pilot which owns the source data,
    so the MeasureCache is still consistent. If a cross-Pilot restore is
    desired, the operator must trigger a manual resync afterwards.
    """
    _check_service_token(request)
    if item_id != _INSTANCE_ID:
        raise HTTPException(status_code=404, detail="Not found")

    body = await request.json()
    data = body.get("data") or {}
    dropped: dict = {}

    # Wipe in FK order: measures depend on findings.
    from sqlalchemy import delete as _delete
    await db.execute(_delete(Measure))
    await db.execute(_delete(Finding))
    # scan_jobs: the export caps at _SCAN_JOB_BACKUP_LIMIT, so a full wipe
    # would destroy history older than the backup window (FEAT-30 audit
    # P1: asymmetric cap). Only wipe the window the backup covers.
    _job_rows = data.get("scan_jobs") or []
    _job_dates = [j.get("created_at") for j in _job_rows if j.get("created_at")]
    if _job_dates:
        try:
            _oldest = datetime.fromisoformat(min(_job_dates))
            await db.execute(_delete(ScanJob).where(ScanJob.created_at >= _oldest))
        except ValueError:
            await db.execute(_delete(ScanJob))
    else:
        # Legacy backups (no timestamps) or empty history: full wipe keeps
        # the old (pre-fix) semantics.
        await db.execute(_delete(ScanJob))
    await db.execute(_delete(MonitoredAsset))
    if "scan_exclusions" in data:
        await db.execute(_delete(ScanExclusion))
    # Only delete the AppSettings rows that the backup is going to
    # rewrite — leaves ai_* and any operator-managed keys intact.
    for s in data.get("app_settings") or []:
        k = s.get("key")
        if k and not k.startswith("ai_"):
            await db.execute(_delete(AppSettings).where(AppSettings.key == k))

    # Restore in FK order: findings before measures (FK), assets first.
    for row in data.get("monitored_assets") or []:
        db.add(MonitoredAsset(**_coerce(MonitoredAsset, row, dropped)))
    for row in data.get("findings") or []:
        db.add(Finding(**_coerce(Finding, row, dropped)))
    await db.flush()
    for row in data.get("measures") or []:
        db.add(Measure(**_coerce(Measure, row, dropped)))
    for row in data.get("scan_jobs") or []:
        db.add(ScanJob(**_coerce(ScanJob, row, dropped)))
    for row in data.get("scan_exclusions") or []:
        db.add(ScanExclusion(**_coerce(ScanExclusion, row, dropped)))
    for s in data.get("app_settings") or []:
        if s.get("key") and not s["key"].startswith("ai_"):
            db.add(AppSettings(key=s["key"], value=s.get("value", "")))

    # Full-instance wipe+reinsert — always journaled (FEAT-30 review).
    from src.audit_common import log_write
    await log_write(db, None, request, "instance.restore", actor="pilot",
                    entity_type="instance", entity_id=_INSTANCE_ID)
    await db.commit()
    return {"ok": True, "action": "restored", "id": _INSTANCE_ID, "dropped_keys": dropped}


@router.post("/internal/sync-user")
async def sync_user(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="email required")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user:
        # Track real changes for the journal (FEAT-30 P3 — no-op pushes stay silent).
        _sync_changed = {k: True for k in ("name", "picture", "role", "ai_enabled")
                         if k in body and getattr(user, k, None) != body[k]}
        if "name" in body:
            user.name = body["name"]
        if "picture" in body:
            user.picture = body["picture"]
        if "role" in body:
            user.role = body["role"]
        if "ai_enabled" in body:
            user.ai_enabled = body["ai_enabled"]
    else:
        user = User(
            email=email, name=body.get("name", ""), picture=body.get("picture", ""),
            provider="pilot", provider_id=body.get("provider_id", email),
            role=body.get("role", "user"),
            ai_enabled=body.get("ai_enabled", "false"),
        )
        db.add(user)
        _sync_changed = {"created": True}
    if _sync_changed:
        from src.audit_common import log_write
        await log_write(db, None, request, "user.sync", actor="pilot",
                        entity_type="user", entity_id=email, details=_sync_changed)
    await db.commit()
    return {"ok": True}


# ── Recovery reads (FEAT-30 phase 2) — state at instant T ───────────────
# The agent's scratch instance holds the database as it was at T. These
# endpoints re-run the exact same export code against it, so Pilot's diff
# compares two payloads of identical shape. The list call also brings the
# scratch schema to head (alembic) when T predates a migration.

@router.get("/internal/export-recovery")
async def internal_export_recovery_list(request: Request):
    _check_service_token(request)
    from src.backup_common import recovery_session, upgrade_recovery_schema
    upgrade_recovery_schema()
    async with recovery_session() as rdb:
        return await internal_export_list(request, rdb)


@router.get("/internal/export-recovery/{item_id}")
async def internal_export_recovery_item(item_id: str, request: Request):
    _check_service_token(request)
    from src.backup_common import recovery_session
    async with recovery_session() as rdb:
        return await internal_export_item(item_id, request, rdb)


# ── Journal reads (FEAT-30 phase 2) — event-anchored restore ────────────
# Pilot's restore UI shows WHO changed WHAT and WHEN so the admin picks an
# event instead of guessing a clock time. Modules whose audit_log predates
# the entity columns (surface/appsec/watch) still serve time+actor+action.

@router.get("/internal/journal")
async def internal_journal(request: Request, entity_id: str = "", limit: int = 30,
                           db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    from src.models import AuditLog
    cols = {c.name for c in AuditLog.__table__.columns}
    q = select(AuditLog).order_by(AuditLog.logged_at.desc()).limit(min(max(limit, 1), 100))
    if entity_id and "entity_id" in cols:
        q = q.where(AuditLog.entity_id == entity_id)
    rows = (await db.execute(q)).scalars().all()
    return [{
        "logged_at": r.logged_at.isoformat() if r.logged_at else None,
        "user_email": r.user_email or "",
        "action": r.action or "",
        "target": r.target or "",
        "entity_type": getattr(r, "entity_type", "") or "",
        "entity_id": getattr(r, "entity_id", "") or "",
        "details": (r.details or "")[:300],
    } for r in rows]


# ── SMTP pushed by Pilot (FEAT: suite-centralized SMTP) ─────────────────
# Suite design rule: the SMTP SERVER config (host/auth/sender) is owned by
# Pilot and pushed here; Surface keeps ownership of report RECIPIENTS and
# scheduling only. Pilot payload keys (host, port, user, password,
# from_addr, tls) map onto Surface's smtp.* app_settings rows.

@router.put("/internal/smtp")
async def internal_smtp(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    body = await request.json()
    mapping = {
        "host": "smtp.host",
        "port": "smtp.port",
        "user": "smtp.username",
        "password": "smtp.password",
        "from_addr": "smtp.sender",
    }
    for src_key, dst_key in mapping.items():
        if src_key in body and str(body[src_key] or "") != "":
            stored = str(body[src_key])
            if src_key == "password":
                stored = encrypt_setting_or_plain(stored)
            row = (await db.execute(
                select(AppSettings).where(AppSettings.key == dst_key)
            )).scalar_one_or_none()
            if row is None:
                db.add(AppSettings(key=dst_key, value=stored))
            else:
                row.value = stored
    if "tls" in body and str(body["tls"] or "") != "":
        val = "1" if str(body["tls"]).lower() in ("1", "true", "yes") else "0"
        row = (await db.execute(
            select(AppSettings).where(AppSettings.key == "smtp.use_tls")
        )).scalar_one_or_none()
        if row is None:
            db.add(AppSettings(key="smtp.use_tls", value=val))
        else:
            row.value = val
    await db.commit()
    logger.info("smtp config received from pilot (host=%s)", body.get("host", ""))
    return {"ok": True}


@router.post("/internal/notification-test")
async def internal_notification_test(request: Request, db: AsyncSession = Depends(get_db)):
    """FEAT-35 — Pilot's 'run a test' triggers Surface's alert-style test
    for the caller. Respects the user's surface enabled flag."""
    _check_service_token(request)
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=422, detail="email required")
    from src.surface_notify import surface_prefs_of, send_test_alert
    import httpx as _httpx
    import os as _os
    prefs = None
    pilot_url = _os.getenv("PILOT_URL", "")
    if pilot_url:
        try:
            async with _httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    pilot_url.rstrip("/") + "/api/internal/notification-prefs/lookup",
                    headers={"X-Service-Token": _os.getenv("SERVICE_TOKEN", "")},
                    json={"emails": [email]})
            if resp.is_success:
                full = resp.json().get(email)
                prefs = surface_prefs_of(full) if full else None
        except _httpx.HTTPError:
            prefs = None
    if not prefs or not prefs.get("alert_enabled"):
        return {"status": "skipped_disabled"}
    return {"status": await send_test_alert(db, email, prefs)}
