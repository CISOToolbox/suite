"""Suite-integration endpoints for the Watch module.

Phase 0 ships:
  - GET  /api/internal/stats        → empty Pilot envelope (no data yet)
  - GET  /api/internal/measures     → fixed zeroes (Watch never escalates
                                       to Pilot measures per decision #6)
  - POST /api/internal/sync-user    → Pilot pushes user metadata
  - PUT  /api/internal/ai-custom    → Pilot pushes managed-LLM config
                                       (consumed by src/routes/ai.py)

Phases 1+ fill /stats with real watchlist/alert KPIs. The /measures
shape stays at zero on purpose: per design we do NOT promote Watch
alerts into Pilot's consolidated action plan — that's already covered
by AppSec for vulnerability remediation.
"""
from __future__ import annotations

import logging
import os
import secrets

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Depends
from sqlalchemy import select, func, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session, get_db
from src.models import Alert, AlertMatch, AppSettings, Scope, User, WatchTarget
from src.settings_crypto import decrypt_setting, encrypt_setting_or_plain

logger = logging.getLogger("watch.internal")

router = APIRouter(prefix="/api", tags=["internal"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
MODULE_NAME = os.getenv("MODULE_NAME", "watch")

# Custom LLM config pushed by Pilot at PUT /internal/ai-custom.
# Read by src/routes/ai.py through src.routes.internal._custom_llm
# (cross-module-internal contract — do not rename without updating ai.py).
_custom_llm: dict = {}

# SMTP config pushed by Pilot at PUT /internal/smtp. Read by
# src/digest.py through src.routes.internal._smtp_config.
# Keys: host, port, user, password, from_addr, tls. The in-memory dict is
# the hot read path for the sync ``_send_smtp`` helper; it is mirrored to
# ``app_settings`` (rows ``smtp.<field>``) so the config survives a Watch
# rebuild / Pilot downtime. Hydrated from DB at app startup.
_smtp_config: dict = {}

_SMTP_FIELDS = ("host", "port", "user", "password", "from_addr", "tls")


async def _hydrate_smtp_from_db() -> None:
    """Prime ``_smtp_config`` from ``app_settings`` rows ``smtp.*``.

    Called once at app startup so the digest scheduler has SMTP available
    on the first tick after a rebuild (without waiting for Pilot to re-push).
    """
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
    except Exception as exc:  # pragma: no cover — defensive: never block startup
        logger.warning("smtp hydrate skipped: %s", exc)


def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    if not token or not secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


@router.get("/internal/stats")
async def internal_stats(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    # Phase 6: real Pilot envelope. Per the contract in
    # shared/docs/pilot-dashboard-contract.md, Watch posts a donut breakdown
    # of alerts per severity, a posture score derived from open KEV ratio,
    # and the top critical/high alerts of the last 7 days.
    now = datetime.now(timezone.utc)
    cutoff_7d = now - timedelta(days=7)

    scopes_count = (await db.execute(select(func.count(Scope.id)))).scalar_one()
    targets_enabled = (await db.execute(
        select(func.count(WatchTarget.id)).where(WatchTarget.enabled == True)  # noqa: E712
    )).scalar_one()
    matched_alert_ids_q = select(distinct(AlertMatch.alert_id))
    matched_alert_ids = [r for r in (await db.execute(matched_alert_ids_q)).scalars().all()]

    # Severity buckets across the system (alerts that actually matched at least one target).
    sev_rows = []
    kev_count = 0
    crit_count = 0
    high_count = 0
    if matched_alert_ids:
        sev_rows = (await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.id.in_(matched_alert_ids))
            .group_by(Alert.severity)
        )).all()
        kev_count = (await db.execute(
            select(func.count(Alert.id)).where(
                Alert.id.in_(matched_alert_ids),
                Alert.kev_listed == True,  # noqa: E712
            )
        )).scalar_one()
    sev_map = {row[0] or "unknown": int(row[1]) for row in sev_rows}
    crit_count = sev_map.get("critical", 0)
    high_count = sev_map.get("high", 0)

    breakdown_data = [
        {"label": s, "value": sev_map[s]}
        for s in ("critical", "high", "medium", "low", "unknown")
        if sev_map.get(s, 0) > 0
    ]

    # Posture: lower KEV ratio → better posture (0..100 score where 100 = no KEV).
    total_matched = sum(sev_map.values()) if sev_map else 0
    if total_matched == 0:
        posture_score = None
        posture_label = ""
    else:
        kev_ratio = kev_count / total_matched
        # 0 KEV → 100; 10%+ KEV → drops to <50; clamp 0..100.
        score = max(0.0, min(100.0, (1.0 - min(kev_ratio * 10, 1.0)) * 100.0))
        # Soften by critical/high share too.
        ch_ratio = (crit_count + high_count) / max(1, total_matched)
        score = max(0.0, score - ch_ratio * 30.0)
        posture_score = round(score, 1)
        if score >= 75:
            posture_label = "Healthy"
        elif score >= 50:
            posture_label = "Monitor"
        elif score >= 25:
            posture_label = "Degraded"
        else:
            posture_label = "Critical"

    # Top items: recent critical/high/KEV alerts of last 7 days.
    top_items: list[dict] = []
    alerts_list: list[dict] = []
    if matched_alert_ids:
        recent = (await db.execute(
            select(Alert)
            .where(
                Alert.id.in_(matched_alert_ids),
                (Alert.kev_listed == True) | (Alert.severity.in_(["critical", "high"])),  # noqa: E712
                Alert.published_at >= cutoff_7d,
            )
            .order_by(Alert.kev_listed.desc(), Alert.published_at.desc().nullslast())
            .limit(10)
        )).scalars().all()
        for a in recent:
            top_items.append({
                "id": str(a.id),
                "label": a.external_id,
                "title": a.title,
                "severity": a.severity,
                "kev_listed": bool(a.kev_listed),
                "published_at": a.published_at.isoformat() if a.published_at else None,
            })
        # alerts[] surface (Pilot consolidated header).
        alerts_list = [
            {
                "level": ("critical" if a.kev_listed or a.severity == "critical" else "warning"),
                "title": a.external_id + " — " + (a.title[:80] if a.title else ""),
                "module": MODULE_NAME,
            }
            for a in recent[:5]
        ]

    return {
        "entity_count": int(scopes_count),
        "entity_label": "Scopes",
        "measures": {"total": 0, "completed": 0, "in_progress": 0, "planned": 0, "overdue": 0, "progress_pct": 0},
        "posture": {"score": posture_score, "score_label": posture_label},
        "breakdown": {"type": "donut", "data": breakdown_data},
        "top_items": top_items,
        "alerts": alerts_list,
        "activity": [],
        # Watch-specific extras (ignored by Pilot but useful for debugging).
        "_extras": {
            "targets_enabled": int(targets_enabled),
            "alerts_matched": int(total_matched),
            "kev_count": int(kev_count),
        },
    }


@router.get("/internal/measures")
async def internal_measures(request: Request):
    _check_service_token(request)
    # Watch does not feed Pilot's measure consolidation (decision #6).
    # The Pilot sync contract expects a list of measure dicts — return [].
    # (Previously returned a stats dict, which broke Pilot's POST /measures/sync
    #  with `'str' object has no attribute 'get'` when iterating dict keys.)
    return []


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
            email=email,
            name=body.get("name", ""),
            picture=body.get("picture", ""),
            provider="pilot",
            provider_id=body.get("provider_id", email),
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



@router.post("/internal/delete-user")
async def delete_user(request: Request, db: AsyncSession = Depends(get_db)):
    """De-provision a user deleted in Pilot.

    Pilot owns the account directory, but each module keeps its own `users`
    row (that is where the module role lives). Without this route a deleted
    person kept a role here for ever: `/internal/sync-user` only creates and
    updates, so nothing ever removed anything.

    Objects the person owned are KEPT — `owner_id` is ON DELETE SET NULL —
    only the account row and the role go.
    """
    _check_service_token(request)
    from sqlalchemy import func as _func

    from src.models import User as LocalUser
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=422, detail="email required")
    target = (await db.execute(
        select(LocalUser).where(_func.lower(LocalUser.email) == email)
    )).scalar_one_or_none()
    if target is None:
        return {"ok": True, "deleted": False}
    from src.audit import log_write
    await log_write(db, None, request, "user.delete", actor="pilot",
                    entity_type="user", entity_id=email,
                    details={"role": target.role or ""})
    await db.delete(target)
    await db.commit()
    return {"ok": True, "deleted": True}

@router.put("/internal/ai-custom")
async def set_ai_custom(request: Request):
    _check_service_token(request)
    body = await request.json()
    _custom_llm.update(body)
    return {"ok": True}


@router.put("/internal/smtp")
async def set_smtp(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive SMTP config pushed by Pilot. Consumed by src/digest.py.

    Persists to ``app_settings`` (rows ``smtp.<field>``) so the config
    survives a Watch rebuild and is available again on the next startup
    without waiting for Pilot to re-push.
    """
    _check_service_token(request)
    body = await request.json()
    # Replace (not update) so removing a field in Pilot actually clears it.
    _smtp_config.clear()
    incoming: dict = {}
    for k in _SMTP_FIELDS:
        if k in body and body[k] not in (None, ""):
            _smtp_config[k] = str(body[k])
            incoming[k] = str(body[k])
    # Mirror to DB: upsert provided fields, delete those absent / cleared.
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
        else:
            if row is not None:
                await db.delete(row)
    await db.commit()
    logger.info("smtp config received from pilot (host=%s)", _smtp_config.get("host", ""))
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
# EXPORT / RESTORE — full-state snapshot for Pilot backups (FEAT-30).
# Single-instance model, same envelope as Surface/AppSec. Users,
# audit_log and feed_state are intentionally NOT included:
#   - users come from Pilot provisioning (sync-user)
#   - audit_log is per-instance and immutable
#   - feed_state is an ingestion cursor, not user data (after a restore
#     the feeds re-scan from their own horizon; alerts dedup on
#     source/external_id)
# scopes.owner_id / alert_statuses.user_id reference users, which are
# NOT in the backup — same-instance restore assumption (as Surface).
# ═══════════════════════════════════════════════════════════════

from src.backup_common import coerce as _bk_coerce, row_dict as _bk_row
from src.models import (
    AlertAnalysis as _BkAnalysis,
    AlertStatus as _BkStatus,
    DigestRun as _BkDigest,
    ScopeRecipient as _BkRecipient,
)

_INSTANCE_ID = "watch"


@router.get("/internal/export")
async def internal_export_list(request: Request, db: AsyncSession = Depends(get_db)):
    """Single-item list — Watch has no project granularity."""
    _check_service_token(request)
    return [{
        "id": _INSTANCE_ID,
        "name": "Watch instance",
        "organization": "",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }]


@router.get("/internal/export/{item_id}")
async def internal_export_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Full state snapshot. ``item_id`` must equal ``watch``."""
    _check_service_token(request)
    if item_id != _INSTANCE_ID:
        raise HTTPException(status_code=404, detail="Not found")

    scopes = (await db.execute(select(Scope))).scalars().all()
    recipients = (await db.execute(select(_BkRecipient))).scalars().all()
    targets = (await db.execute(select(WatchTarget))).scalars().all()
    alerts = (await db.execute(select(Alert))).scalars().all()
    matches = (await db.execute(select(AlertMatch))).scalars().all()
    statuses = (await db.execute(select(_BkStatus))).scalars().all()
    analyses = (await db.execute(select(_BkAnalysis))).scalars().all()
    digests = (await db.execute(select(_BkDigest))).scalars().all()
    settings_rows = (await db.execute(select(AppSettings))).scalars().all()
    safe_settings = [
        {"key": s.key, "value": s.value}
        for s in settings_rows if not s.key.startswith("ai_")
    ]

    return {
        "id": _INSTANCE_ID,
        "name": "Watch instance",
        "organization": "",
        "data": {
            "scopes": [_bk_row(s) for s in scopes],
            "scope_recipients": [_bk_row(r) for r in recipients],
            "watch_targets": [_bk_row(t) for t in targets],
            "alerts": [_bk_row(a) for a in alerts],
            "alert_matches": [_bk_row(m) for m in matches],
            "alert_statuses": [_bk_row(s) for s in statuses],
            "alert_analyses": [_bk_row(a) for a in analyses],
            "digest_runs": [_bk_row(d) for d in digests],
            "app_settings": safe_settings,
        },
    }


@router.put("/internal/restore/{item_id}")
async def internal_restore_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Overwrite the instance state with the backup payload.
    Wipe + re-insert in FK order; users / audit_log / feed_state / ai_*
    preserved. Dropped (unknown-schema) keys are counted and returned."""
    _check_service_token(request)
    if item_id != _INSTANCE_ID:
        raise HTTPException(status_code=404, detail="Not found")

    body = await request.json()
    data = body.get("data") or {}
    dropped: dict = {}

    from sqlalchemy import delete as _delete
    # Children before parents.
    await db.execute(_delete(_BkAnalysis))
    await db.execute(_delete(_BkStatus))
    await db.execute(_delete(AlertMatch))
    await db.execute(_delete(_BkDigest))
    await db.execute(_delete(Alert))
    await db.execute(_delete(WatchTarget))
    await db.execute(_delete(_BkRecipient))
    await db.execute(_delete(Scope))
    for s in data.get("app_settings") or []:
        k = s.get("key")
        if k and not k.startswith("ai_"):
            await db.execute(_delete(AppSettings).where(AppSettings.key == k))

    for row in data.get("scopes") or []:
        db.add(Scope(**_bk_coerce(Scope, row, dropped)))
    await db.flush()
    for row in data.get("scope_recipients") or []:
        db.add(_BkRecipient(**_bk_coerce(_BkRecipient, row, dropped)))
    for row in data.get("watch_targets") or []:
        db.add(WatchTarget(**_bk_coerce(WatchTarget, row, dropped)))
    for row in data.get("alerts") or []:
        db.add(Alert(**_bk_coerce(Alert, row, dropped)))
    await db.flush()
    for row in data.get("alert_matches") or []:
        db.add(AlertMatch(**_bk_coerce(AlertMatch, row, dropped)))
    for row in data.get("alert_statuses") or []:
        db.add(_BkStatus(**_bk_coerce(_BkStatus, row, dropped)))
    for row in data.get("alert_analyses") or []:
        db.add(_BkAnalysis(**_bk_coerce(_BkAnalysis, row, dropped)))
    for row in data.get("digest_runs") or []:
        db.add(_BkDigest(**_bk_coerce(_BkDigest, row, dropped)))
    for s in data.get("app_settings") or []:
        if s.get("key") and not s["key"].startswith("ai_"):
            db.add(AppSettings(key=s["key"], value=s.get("value", "")))

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
