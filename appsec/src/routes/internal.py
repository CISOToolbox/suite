from __future__ import annotations

import logging
import os
import secrets
from datetime import date as _date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select, case as sa_case
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session, get_db
from src.models import Application, AppSettings, Finding, Measure, ScanJob, User

logger = logging.getLogger("appsec.internal")

router = APIRouter(prefix="/api", tags=["internal"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
MODULE_NAME = os.getenv("MODULE_NAME", "appsec")
PILOT_URL = os.getenv("PILOT_URL", "")

_custom_llm: dict = {}


def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    if not token or not secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


def _normalize_status(s: str) -> str:
    return {"termine": "completed", "completed": "completed",
            "en_cours": "in_progress", "in_progress": "in_progress",
            "a_faire": "planned", "planifie": "planned", "planned": "planned"}.get(s, s)


def _denormalize_status(s: str) -> str:
    return {"completed": "termine", "in_progress": "en_cours", "planned": "a_faire"}.get(s, s)


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


@router.get("/internal/stats")
async def internal_stats(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)

    total_apps = await db.scalar(select(func.count()).select_from(Application)) or 0
    open_filter = Finding.status.in_(["new", "to_fix"])

    crit = await db.scalar(select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "critical")) or 0
    high = await db.scalar(select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "high")) or 0
    med = await db.scalar(select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "medium")) or 0
    low = await db.scalar(select(func.count()).select_from(Finding).where(open_filter, Finding.severity == "low")) or 0
    total_findings = await db.scalar(select(func.count()).select_from(Finding)) or 0

    measure_rows = (await db.execute(select(Measure.statut, func.count()).group_by(Measure.statut))).all()
    measure_counts = {s: c for s, c in measure_rows}
    total_measures = sum(measure_counts.values())
    completed = measure_counts.get("termine", 0)
    in_progress = measure_counts.get("en_cours", 0)
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
        {"label": "High", "value": high, "color": "red"},
        {"label": "Medium", "value": med, "color": "orange"},
        {"label": "Low", "value": low, "color": "yellow"},
    ]
    scale = max((b["value"] for b in buckets), default=1) or 1

    app_sev = (
        select(Application.name, func.count().label("cnt"),
               func.sum(sa_case((Finding.severity == "critical", 10), (Finding.severity == "high", 3), else_=1)).label("weight"))
        .join(Finding, Finding.application_id == Application.id)
        .where(open_filter)
        .group_by(Application.name)
        .order_by(func.sum(sa_case((Finding.severity == "critical", 10), (Finding.severity == "high", 3), else_=1)).desc())
        .limit(3)
    )
    app_result = await db.execute(app_sev)
    top_items = [{
        "id": row.name, "label": (row.name or "")[:80],
        "severity": "critical" if row.weight >= 10 else "high",
        "url": "/appsec/", "meta": f"{row.cnt} finding(s)",
    } for row in app_result.all()]

    alerts = []
    if crit > 0:
        alerts.append({"level": "critical", "text": f"{crit} finding(s) critique(s) ouvert(s)", "url": "/appsec/"})
    if overdue > 0:
        alerts.append({"level": "warning", "text": f"{overdue} mesure(s) en retard", "url": "/appsec/"})

    return {
        "entity_count": total_apps, "entity_label": "Applications",
        "measures": {"total": total_measures, "completed": completed, "in_progress": in_progress,
                     "planned": planned, "overdue": overdue, "progress_pct": progress_pct},
        "posture": {"score": posture_score, "score_label": _posture_label(posture_score)},
        "breakdown": {"type": "bar", "data": {"buckets": buckets, "scale": scale, "unit": ""}},
        "top_items": top_items, "alerts": alerts,
        "total_findings": total_findings, "critical_findings": crit, "high_findings": high,
    }


@router.get("/internal/activity")
async def internal_activity(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    recent = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(10))
    events = []
    for j in recent.scalars().all():
        ts = (j.created_at or datetime.now(timezone.utc)).isoformat()
        app_q = await db.execute(select(Application.name).where(Application.id == j.application_id))
        app_name = app_q.scalar() or ""
        events.append({
            "date": ts, "module": MODULE_NAME,
            "type": "scan_completed" if j.status == "completed" else "scan_" + (j.status or ""),
            "label": f"Scan {j.scanner} — {app_name} ({j.findings_count} findings)",
            "url": "/appsec/",
        })
    return events[:10]


@router.get("/internal/measures")
async def internal_measures(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    result = await db.execute(
        select(Measure, Finding).join(Finding, Measure.finding_id == Finding.id).order_by(Measure.sort_order)
    )
    out = []
    for m, f in result.all():
        app_q = await db.execute(select(Application.name).where(Application.id == f.application_id))
        app_name = app_q.scalar() or ""
        out.append({
            "source_id": m.id, "entity_id": str(f.id),
            "entity_name": f"{app_name} — {f.target or f.title}",
            "title": m.title,
            "description": m.description or "",
            "status": _normalize_status(m.statut),
            "assignee": m.responsable or "", "due_date": m.echeance or "",
            "progress_log": m.progress_log or [],
            "type": f.type, "severity": f.severity, "source_module": MODULE_NAME,
        })
    return out


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
        m.statut = _denormalize_status(body["status"])
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
    return {"ok": True}


@router.delete("/internal/measures/{source_id}", status_code=204)
async def delete_measure_internal(source_id: str, request: Request, db: AsyncSession = Depends(get_db)):
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
        if "name" in body: user.name = body["name"]
        if "picture" in body: user.picture = body["picture"]
        if "role" in body: user.role = body["role"]
        if "ai_enabled" in body: user.ai_enabled = body["ai_enabled"]
    else:
        user = User(email=email, name=body.get("name", ""), picture=body.get("picture", ""),
                    provider="pilot", provider_id=body.get("provider_id", email), role=body.get("role", "user"),
                    ai_enabled=body.get("ai_enabled", "false"))
        db.add(user)
        _sync_changed = {"created": True}
    if _sync_changed:
        from src.audit_common import log_write
        await log_write(db, None, request, "user.sync", actor="pilot",
                        entity_type="user", entity_id=email, details=_sync_changed)
    await db.commit()
    return {"ok": True}


@router.put("/internal/ai-custom")
async def set_ai_custom(request: Request):
    _check_service_token(request)
    body = await request.json()
    _custom_llm.update(body)
    return {"ok": True}


@router.post("/internal/sbom/impact")
async def sbom_impact(request: Request, db: AsyncSession = Depends(get_db)):
    """Suite-integration endpoint consumed by Watch to compute the SBOM
    impact of an alert.

    Body:
      {
        "cve_id": "CVE-2025-12345",          # optional
        "affected": [                         # optional, list of feed-side hints
          {"vendor":"openssl","product":"openssl","cpe":"cpe:2.3:...","version_range":"<3.0.0"},
          {"purl":"pkg:npm/lodash","version_range":"<4.17.21"},
          ...
        ]
      }

    Returns the list of (application, package@version) tuples that match
    on either:
      - a direct CVE finding (`Finding.cve_id == cve_id`), or
      - an SBOM entry whose package_name matches the OSV `purl` name part,
      - an SBOM entry whose package_name matches the affected `product` slug.

    Watch is responsible for the version-range intersection — AppSec only
    surfaces all package versions present in any SBOM (the version is
    returned so Watch can do its semver check).
    """
    from src.models import Application, SBOMEntry  # local import keeps cold-path light
    _check_service_token(request)
    body = await request.json()
    cve_id = (body.get("cve_id") or "").strip().upper()
    affected = body.get("affected") or []

    # Build the list of package-name hints from the affected[] payload.
    pkg_hints: set[str] = set()
    for a in affected:
        if not isinstance(a, dict):
            continue
        purl = (a.get("purl") or "").lower()
        if purl.startswith("pkg:"):
            # pkg:ecosystem/name[@ver]
            rest = purl.split(":", 1)[1]
            try:
                _, name_ver = rest.split("/", 1)
            except ValueError:
                continue
            name = name_ver.split("@", 1)[0].split("?", 1)[0]
            if name:
                pkg_hints.add(name.lower())
        product = (a.get("product") or "").strip().lower()
        if product:
            pkg_hints.add(product)
        vendor = (a.get("vendor") or "").strip().lower()
        if vendor and len(vendor) > 2:
            pkg_hints.add(vendor)

    matched_findings: list[dict] = []
    if cve_id:
        rows = (await db.execute(
            select(Finding.application_id, Finding.target, Finding.status, Finding.severity)
            .where(Finding.type == "cve", Finding.cve_id == cve_id)
        )).all()
        for app_id, target, status, severity in rows:
            matched_findings.append({
                "application_id": str(app_id),
                "target": target or "",
                "status": status,
                "severity": severity or "",
                "source": "finding",
            })

    matched_sbom: list[dict] = []
    if pkg_hints:
        # ILIKE OR over each hint; capped at 500 hits to keep the response small.
        from sqlalchemy import or_ as sa_or
        clauses = [SBOMEntry.package_name.ilike(f"%{h}%") for h in pkg_hints]
        rows = (await db.execute(
            select(SBOMEntry.application_id, SBOMEntry.package_name,
                   SBOMEntry.version, SBOMEntry.ecosystem)
            .where(sa_or(*clauses))
            .limit(500)
        )).all()
        for app_id, name, ver, eco in rows:
            matched_sbom.append({
                "application_id": str(app_id),
                "package_name": name,
                "version": ver or "",
                "ecosystem": eco or "",
                "source": "sbom",
            })

    # Resolve application names in one round-trip.
    app_ids = list({m["application_id"] for m in matched_findings + matched_sbom})
    app_names: dict[str, str] = {}
    if app_ids:
        import uuid as _uuid
        try:
            app_rows = (await db.execute(
                select(Application.id, Application.name)
                .where(Application.id.in_([_uuid.UUID(a) for a in app_ids]))
            )).all()
            app_names = {str(rid): rname for rid, rname in app_rows}
        except Exception:
            app_names = {}
    for m in matched_findings + matched_sbom:
        m["application_name"] = app_names.get(m["application_id"], "")

    return {
        "cve_id": cve_id or None,
        "matched_findings": matched_findings,
        "matched_sbom": matched_sbom,
        "applications": sorted({m["application_name"] for m in matched_findings + matched_sbom if m["application_name"]}),
    }


# ═══════════════════════════════════════════════════════════════
# EXPORT / RESTORE — full-state snapshot for Pilot backups (FEAT-30).
# Single-instance model (no project granularity), same envelope as
# Surface. Users and audit_log are intentionally NOT included:
#   - users come from Pilot provisioning (sync-user)
#   - audit_log is per-instance and immutable
# The restore assumes the same Pilot owns the source data (same-instance
# restore); a cross-Pilot restore requires a manual measures resync.
# ═══════════════════════════════════════════════════════════════

from src.backup_common import coerce as _bk_coerce, row_dict as _bk_row
from src.models import AppSettings as _BkSettings, IgnoreRule as _BkIgnoreRule, SBOMEntry as _BkSBOM

_INSTANCE_ID = "appsec"


@router.get("/internal/export")
async def internal_export_list(request: Request, db: AsyncSession = Depends(get_db)):
    """Single-item list — AppSec has no project granularity."""
    _check_service_token(request)
    return [{
        "id": _INSTANCE_ID,
        "name": "AppSec instance",
        "organization": "",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }]


@router.get("/internal/export/{item_id}")
async def internal_export_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Full state snapshot. ``item_id`` must equal ``appsec``."""
    _check_service_token(request)
    if item_id != _INSTANCE_ID:
        raise HTTPException(status_code=404, detail="Not found")

    applications = (await db.execute(select(Application))).scalars().all()
    scan_jobs = (await db.execute(select(ScanJob))).scalars().all()
    findings = (await db.execute(select(Finding))).scalars().all()
    measures = (await db.execute(select(Measure))).scalars().all()
    sbom = (await db.execute(select(_BkSBOM))).scalars().all()
    ignore_rules = (await db.execute(select(_BkIgnoreRule))).scalars().all()
    settings_rows = (await db.execute(select(_BkSettings))).scalars().all()
    safe_settings = [
        {"key": s.key, "value": s.value}
        for s in settings_rows if not s.key.startswith("ai_")
    ]

    return {
        "id": _INSTANCE_ID,
        "name": "AppSec instance",
        "organization": "",
        "data": {
            "applications": [_bk_row(a) for a in applications],
            "scan_jobs": [_bk_row(j) for j in scan_jobs],
            "findings": [_bk_row(f) for f in findings],
            "measures": [_bk_row(m) for m in measures],
            "sbom_entries": [_bk_row(s) for s in sbom],
            "ignore_rules": [_bk_row(r) for r in ignore_rules],
            "app_settings": safe_settings,
        },
    }


@router.put("/internal/restore/{item_id}")
async def internal_restore_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Overwrite the instance state with the backup payload.
    Wipe + re-insert in FK order; users / audit_log / ai_* preserved.
    Dropped (unknown-schema) keys are counted and returned, not silent."""
    _check_service_token(request)
    if item_id != _INSTANCE_ID:
        raise HTTPException(status_code=404, detail="Not found")

    body = await request.json()
    data = body.get("data") or {}
    dropped: dict = {}

    from sqlalchemy import delete as _delete
    # Children before parents (measures → findings/sbom/jobs → applications).
    await db.execute(_delete(Measure))
    await db.execute(_delete(Finding))
    await db.execute(_delete(_BkSBOM))
    await db.execute(_delete(ScanJob))
    await db.execute(_delete(Application))
    await db.execute(_delete(_BkIgnoreRule))
    for s in data.get("app_settings") or []:
        k = s.get("key")
        if k and not k.startswith("ai_"):
            await db.execute(_delete(_BkSettings).where(_BkSettings.key == k))

    for row in data.get("applications") or []:
        db.add(Application(**_bk_coerce(Application, row, dropped)))
    await db.flush()
    for row in data.get("scan_jobs") or []:
        db.add(ScanJob(**_bk_coerce(ScanJob, row, dropped)))
    for row in data.get("findings") or []:
        db.add(Finding(**_bk_coerce(Finding, row, dropped)))
    for row in data.get("sbom_entries") or []:
        db.add(_BkSBOM(**_bk_coerce(_BkSBOM, row, dropped)))
    await db.flush()
    for row in data.get("measures") or []:
        db.add(Measure(**_bk_coerce(Measure, row, dropped)))
    for row in data.get("ignore_rules") or []:
        db.add(_BkIgnoreRule(**_bk_coerce(_BkIgnoreRule, row, dropped)))
    for s in data.get("app_settings") or []:
        if s.get("key") and not s["key"].startswith("ai_"):
            db.add(_BkSettings(key=s["key"], value=s.get("value", "")))

    # Full-instance wipe+reinsert — always journaled (FEAT-30 review).
    from src.audit_common import log_write
    await log_write(db, None, request, "instance.restore", actor="pilot",
                    entity_type="instance", entity_id=_INSTANCE_ID)
    await db.commit()
    return {"ok": True, "action": "restored", "id": _INSTANCE_ID, "dropped_keys": dropped}


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


# ── FEAT-35 — SMTP pushed by Pilot (standard receiver, asset pattern) ──────
# Consumed by src/findings_notify.py. Persisted to app_settings rows
# smtp.<field> (password encrypted at rest) so the config survives a rebuild
# and is hydrated at startup without a Pilot re-push.

_SMTP_FIELDS = ("host", "port", "user", "password", "from_addr", "tls")
_smtp_config: dict = {}


async def _hydrate_smtp_from_db() -> None:
    """Prime _smtp_config from app_settings rows smtp.* (called at startup)."""
    from src.settings_crypto import decrypt_setting
    try:
        async with async_session() as db:
            rows = (await db.execute(
                select(AppSettings).where(AppSettings.key.like("smtp.%"))
            )).scalars().all()
        loaded = {}
        for row in rows:
            field = row.key.split(".", 1)[1]
            if field in _SMTP_FIELDS and row.value not in (None, ""):
                loaded[field] = decrypt_setting(row.value) if field == "password" else row.value
        if loaded:
            _smtp_config.clear()
            _smtp_config.update(loaded)
            logger.info("smtp config hydrated from app_settings (host=%s)", loaded.get("host", ""))
    except Exception as exc:  # defensive: never block startup
        logger.warning("smtp hydrate skipped: %s", exc)


@router.put("/internal/smtp")
async def set_smtp(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive SMTP config pushed by Pilot (FEAT-35 notifications)."""
    from src.settings_crypto import encrypt_setting_or_plain
    _check_service_token(request)
    body = await request.json()
    _smtp_config.clear()
    incoming: dict = {}
    for k in _SMTP_FIELDS:
        if k in body and body[k] not in (None, ""):
            _smtp_config[k] = str(body[k])
            incoming[k] = str(body[k])
    existing = (await db.execute(
        select(AppSettings).where(AppSettings.key.like("smtp.%"))
    )).scalars().all()
    existing_by_key = {row.key: row for row in existing}
    for field in _SMTP_FIELDS:
        key = f"smtp.{field}"
        row = existing_by_key.get(key)
        if field in incoming:
            stored = encrypt_setting_or_plain(incoming[field]) if field == "password" else incoming[field]
            if row is None:
                db.add(AppSettings(key=key, value=stored))
            else:
                row.value = stored
        elif row is not None:
            await db.delete(row)
    await db.commit()
    logger.info("smtp config received from pilot (host=%s)", _smtp_config.get("host", ""))
    return {"ok": True}


@router.post("/internal/notification-test")
async def internal_notification_test(request: Request, db: AsyncSession = Depends(get_db)):
    """FEAT-35 — Pilot's 'run a test' triggers AppSec's weekly-recap test
    for the caller. Respects the user's appsec enabled flags."""
    _check_service_token(request)
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=422, detail="email required")
    from src.findings_notify import (
        APPSEC_PREF_DEFAULTS, resolve_recipient_prefs, send_weekly_for_recipient)
    prefs_map = await resolve_recipient_prefs(db, [email])
    prefs = prefs_map.get(email, dict(APPSEC_PREF_DEFAULTS))
    if not (prefs.get("alert_enabled") or prefs.get("weekly_enabled")):
        return {"status": "skipped_disabled"}
    apps = (await db.execute(
        select(Application).where(Application.enabled.is_(True))
    )).scalars().all()
    mine = [a for a in apps
            if email in [(e or "").strip().lower() for e in (a.notification_emails or [])]]
    return {"status": await send_weekly_for_recipient(db, email, mine or apps, prefs, force=True)}
