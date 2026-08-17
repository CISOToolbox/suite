"""Internal API endpoints for Pilot integration."""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session, get_db
from src.models import AppSettings, Asset, AssetGroup, Measure, Project
from src.settings_crypto import decrypt_setting, encrypt_setting_or_plain

router = APIRouter(prefix="/api", tags=["internal"])


def _normalize_status(s: str) -> str:
    """Asset statut → Pilot transverse status."""
    mapping = {
        "termine": "completed", "Terminé": "completed", "completed": "completed",
        "en_cours": "in_progress", "in_progress": "in_progress",
        "a_faire": "planned", "planifie": "planned", "planned": "planned",
    }
    return mapping.get((s or "").strip(), s)

logger = logging.getLogger("asset-internal")

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

# SMTP config pushed by Pilot at PUT /internal/smtp, read by src/mailer.py
# through src.routes.internal._smtp_config. Mirrored to app_settings
# (rows smtp.<field>) so it survives a rebuild; hydrated at startup.
_smtp_config: dict = {}
_SMTP_FIELDS = ("host", "port", "user", "password", "from_addr", "tls")


async def _hydrate_smtp_from_db() -> None:
    """Prime _smtp_config from app_settings rows smtp.* (called at startup)."""
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




def _validate_proxy_url(url: str) -> None:
    """Reject a proxy URL that points at an internal target.

    Delegates to the shared ssrf_guard rather than re-implementing the
    blocklist. The local version this replaces swallowed socket.gaierror, so a
    name that failed to resolve was ACCEPTED — the opposite of the shared
    guard's fail-closed contract — and it never knew about the Alibaba/Oracle
    metadata IPs, CGNAT, multicast or the reserved blocks.

    It matters more here than at a normal call site: the route below exports
    this value into the process-wide HTTP_PROXY, and httpx runs trust_env=True,
    so it redirects EVERY outbound request the module makes afterwards —
    including ones another guard had carefully pinned to a resolved IP.
    """
    from src.ssrf_guard import validate_public_url

    try:
        # allow_private stays False: the previous implementation already
        # refused RFC1918 proxies, so this is not a behaviour change.
        validate_public_url(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Proxy endpoint not allowed: {e}")



def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")

    token = request.headers.get("X-Service-Token", "")
    import secrets as _secrets
    if not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


@router.get("/internal/stats")
async def internal_stats(request: Request, db: AsyncSession = Depends(get_db)):
    """Stats v2 envelope — see shared/docs/pilot-dashboard-contract.md"""
    _check_service_token(request)

    total_assets = await db.scalar(select(func.count()).select_from(Asset)) or 0
    total_groups = await db.scalar(select(func.count()).select_from(AssetGroup)) or 0

    # ── Assets by criticite ──
    crit_result = await db.execute(
        select(Asset.criticite, func.count()).group_by(Asset.criticite)
    )
    per_crit = {int(row[0] or 0): row[1] for row in crit_result.all()}
    crit_colors = {4: "redMax", 3: "red", 2: "orange", 1: "yellow", 0: "green"}
    crit_labels = {4: "Vitale", 3: "Critique", 2: "Importante", 1: "Standard", 0: "Faible"}
    donut_segments = []
    for c in [4, 3, 2, 1, 0]:
        v = per_crit.get(c, 0)
        if v:
            donut_segments.append({"label": crit_labels[c], "value": v, "color": crit_colors[c]})

    # ── Posture: % of assets with a proprietaire set ──
    owned = await db.scalar(
        select(func.count()).select_from(Asset).where(Asset.proprietaire.isnot(None), Asset.proprietaire != "")
    ) or 0
    unowned = total_assets - owned
    posture_score = round(owned / total_assets * 100) if total_assets else 100

    critical = per_crit.get(4, 0) + per_crit.get(3, 0)

    top_result = await db.execute(
        select(Asset).where(Asset.criticite >= 3).order_by(Asset.criticite.desc()).limit(3)
    )
    top_items = [{
        "id": a.id,
        "label": (a.nom or "")[:80],
        "severity": "critical" if a.criticite >= 4 else "high",
        "url": "/asset/",
    } for a in top_result.scalars().all()]

    alerts = []
    if unowned > 0:
        alerts.append({
            "level": "warning" if unowned < max(1, total_assets * 0.2) else "critical",
            "text": f"{unowned} actif(s) sans propriétaire",
            "url": "/asset/",
        })

    # ── Measures (action plan) counts ──
    from datetime import date as _date
    all_measures = (await db.execute(select(Measure))).scalars().all()
    total_measures = len(all_measures)
    m_completed = m_in_progress = m_planned = m_overdue = 0
    _today = _date.today().isoformat()
    for m in all_measures:
        st = (m.statut or "").strip()
        if st in ("completed", "termine", "Terminé"):
            m_completed += 1
        elif st in ("in_progress", "en_cours"):
            m_in_progress += 1
        else:
            m_planned += 1
        if m.echeance and m.echeance < _today and st not in ("completed", "termine", "Terminé"):
            m_overdue += 1
    m_progress_pct = round(m_completed / total_measures * 100) if total_measures else 0
    if m_overdue > 0:
        alerts.append({
            "level": "warning",
            "text": f"{m_overdue} mesure(s) en retard",
            "url": "/asset/",
        })

    return {
        "entity_count": total_assets,
        "entity_label": "Actifs",
        "measures": {
            "total": total_measures,
            "completed": m_completed,
            "in_progress": m_in_progress,
            "planned": m_planned,
            "overdue": m_overdue,
            "progress_pct": m_progress_pct,
        },
        "posture": {
            "score": posture_score,
            "score_label": _posture_label(posture_score),
        },
        "breakdown": {
            "type": "donut",
            "data": {
                "segments": donut_segments,
                "center_label": str(total_assets),
                "center_sublabel": "actifs",
            },
        },
        "top_items": top_items,
        "alerts": alerts,
        # Legacy
        "total_assets": total_assets,
        "total_groups": total_groups,
        "assets_by_type": {},
        "assets_by_criticite": {str(k): v for k, v in per_crit.items()},
        "critical_assets": critical,
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
        select(Asset).order_by(Asset.updated_at.desc()).limit(10)
    )
    for a in recent.scalars().all():
        events.append({
            "date": (a.updated_at or a.created_at).isoformat(),
            "module": "asset",
            "type": "asset_updated",
            "label": f"Actif « {(a.nom or a.id)[:50]} » mis à jour",
            "url": "/asset/",
        })
    return events[:10]


@router.get("/internal/measures")
async def internal_measures(request: Request, db: AsyncSession = Depends(get_db)):
    """Export Asset measures to Pilot (pilot-dashboard-contract schema)."""
    _check_service_token(request)
    result = await db.execute(select(Measure).order_by(Measure.project_id, Measure.sort_order))
    out = []
    for m in result.scalars().all():
        out.append({
            "source_id": m.id,
            "entity_id": str(m.project_id),
            "entity_name": m.title,
            "title": m.title,
            "description": m.description or "",
            "status": _normalize_status(m.statut),
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
            "type": "asset_renewal" if m.origine == "echeance" else "asset_action",
            "source_module": "asset",
            "progress_log": m.progress_log or [],
        })
    return out


async def bump_server_rev(db, project_id) -> None:
    """FEAT-33 — mark a server-initiated write so stale tabs cannot blob-PUT
    over it (see routes/projects.update_project)."""
    from sqlalchemy import update as _upd
    from src.models import Project as _P
    await db.execute(_upd(_P).where(_P.id == project_id).values(server_rev=_P.server_rev + 1))


@router.patch("/internal/measures/{source_id}")
async def patch_measure_internal(source_id: str, request: Request,
                                 entity_id: str | None = None,
                                 db: AsyncSession = Depends(get_db)):
    """Write-back from Pilot. Measure id is unique only within a project, so
    Pilot passes entity_id (= project_id) to target the exact row."""
    _check_service_token(request)
    body = await request.json()

    q = select(Measure).where(Measure.id == source_id)
    if entity_id:
        q = q.where(Measure.project_id == entity_id)
    measure = (await db.execute(q)).scalar_one_or_none()
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")

    if "title" in body:
        measure.title = body["title"]
    if "description" in body:
        measure.description = body["description"]
    if "status" in body:
        _denorm = {"completed": "termine", "in_progress": "en_cours", "planned": "a_faire"}
        measure.statut = _denorm.get(body["status"], body["status"])
    if "assignee" in body:
        measure.responsable = body["assignee"]
    if "due_date" in body:
        measure.echeance = body["due_date"]
    if "progress_log" in body:
        measure.progress_log = body["progress_log"]
    # Pilot write-back is a business write — journaled (FEAT-30 review).
    from src.audit import log_write
    await log_write(db, None, request, "measure.writeback_update", actor="pilot",
                    entity_type="measure", entity_id=str(source_id))
    await bump_server_rev(db, measure.project_id)
    await db.commit()
    return {"ok": True}


@router.delete("/internal/measures/{source_id}", status_code=204)
async def delete_measure_internal(source_id: str, request: Request,
                                  entity_id: str | None = None,
                                  db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    q = select(Measure).where(Measure.id == source_id)
    if entity_id:
        q = q.where(Measure.project_id == entity_id)
    measure = (await db.execute(q)).scalar_one_or_none()
    if measure:
        # Pilot write-back is a business write — journaled (FEAT-30 review).
        from src.audit import log_write
        await log_write(db, None, request, "measure.writeback_delete", actor="pilot",
                        entity_type="measure", entity_id=str(source_id))
        await db.delete(measure)
        await bump_server_rev(db, measure.project_id)
    await db.commit()


# ── Audit trail for Pilot-pushed config changes (SEC hardening) ──
# set_proxy / set_custom_llm are service-token endpoints (no user), yet they
# change egress routing and the LLM the module talks to. Record the source
# and what changed so a rogue/erroneous push is traceable. Secrets are NEVER
# logged: proxy URLs are stripped of any user:pass and the LLM key is reduced
# to a boolean. Rotate credentials after any unexpected change (runbook).
def _redact_url(url: str) -> str:
    if not url:
        return "(empty)"
    try:
        p = urlparse(url)
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        return f"{p.scheme}://{host}" if host else "(set)"
    except Exception:
        return "(set)"


def _audit_internal_change(request: Request, action: str, details: dict) -> None:
    ip = request.client.host if request and request.client else "?"
    rendered = " ".join(f"{k}={v}" for k, v in details.items())
    logger.warning("internal config change: action=%s src=%s %s", action, ip, rendered)


@router.put("/internal/proxy")
async def set_proxy(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive proxy config from Pilot."""
    _check_service_token(request)
    body = await request.json()
    for key in ("http_proxy", "https_proxy"):
        if key in body:
            _validate_proxy_url(body[key])
    if "http_proxy" in body:
        os.environ["HTTP_PROXY"] = body["http_proxy"]
        os.environ["http_proxy"] = body["http_proxy"]
    if "https_proxy" in body:
        os.environ["HTTPS_PROXY"] = body["https_proxy"]
        os.environ["https_proxy"] = body["https_proxy"]
    if "no_proxy" in body:
        os.environ["NO_PROXY"] = body["no_proxy"]
        os.environ["no_proxy"] = body["no_proxy"]
    changed = {k: _redact_url(body[k]) for k in ("http_proxy", "https_proxy") if k in body}
    if "no_proxy" in body:
        changed["no_proxy"] = body["no_proxy"]
    if changed:
        _audit_internal_change(request, "proxy.set", changed)
    return {"ok": True}


# In-memory custom LLM config (pushed by Pilot)
_custom_llm = {"endpoint": "", "model": "", "key": "", "label": "Custom LLM"}

@router.put("/internal/ai-custom")
async def set_custom_llm(request: Request):
    """Receive custom LLM config from Pilot."""
    _check_service_token(request)
    global _custom_llm
    body = await request.json()
    _custom_llm = {
        "endpoint": body.get("endpoint", ""),
        "model": body.get("model", ""),
        "key": body.get("key", ""),
        "label": body.get("label", "Custom LLM"),
    }
    _audit_internal_change(request, "ai_custom.set", {
        "endpoint": _redact_url(_custom_llm["endpoint"]) if _custom_llm["endpoint"] else "(cleared)",
        "model": _custom_llm["model"] or "(none)",
        "label": _custom_llm["label"],
        "key_set": bool(_custom_llm["key"]),
    })
    return {"ok": True}


@router.post("/internal/sync-user")
async def sync_user(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive user ai_enabled update from Pilot."""
    _check_service_token(request)
    body = await request.json()
    email = body.get("email", "")
    if not email:
        return {"ok": False, "error": "no email"}

    from src.models import User as LocalUser
    result = await db.execute(select(LocalUser).where(LocalUser.email == email))
    user = result.scalar_one_or_none()
    if user:
        changed = {}
        if "ai_enabled" in body and user.ai_enabled != body["ai_enabled"]:
            user.ai_enabled = body["ai_enabled"]
            changed["ai_enabled"] = bool(body["ai_enabled"])
        if "name" in body and body["name"] and user.name != body["name"]:
            user.name = body["name"]
            changed["name"] = True
        if changed:
            # Journal only when something actually changed (FEAT-30 P3).
            from src.audit import log_write
            await log_write(db, None, request, "user.sync", actor="pilot",
                            entity_type="user", entity_id=email, details=changed)
        await db.commit()
        return {"ok": True, "updated": True}
    return {"ok": True, "updated": False, "reason": "user not found in module"}


@router.get("/internal/export")
async def internal_export_list(request: Request, db: AsyncSession = Depends(get_db)):
    """List all projects for Pilot backup."""
    _check_service_token(request)
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    projects = result.scalars().all()
    return [{"id": str(p.id), "name": p.name or "", "organization": p.organization or "", "updated_at": str(p.updated_at)} for p in projects]


@router.get("/internal/export/{item_id}")
async def internal_export_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Export full project data for Pilot backup."""
    _check_service_token(request)
    from src.routes.projects import _reconstruct_data
    project = await db.get(Project, item_id)
    if not project:
        raise HTTPException(status_code=404, detail="Not found")
    data = await _reconstruct_data(db, project.id)
    return {"id": str(project.id), "name": project.name, "organization": project.organization, "data": data}


@router.put("/internal/restore/{item_id}")
async def internal_restore_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Restore project data from Pilot backup.

    Measures are handled HERE and not in _decompose_data: the blob PUT
    (frontend autosave) must never wipe scheduler/Pilot-owned measures
    (FEAT-22), but a Pilot restore is authoritative for the whole state.
    Legacy backups without a ``measures`` key leave the table untouched."""
    _check_service_token(request)
    # Single-project module (CHANTIER_PROJET_UNIQUE): a restore must never
    # resurrect a non-canonical project id (FEAT-30 P1bis — pre-collapse
    # backups carry the old random id). Repoint onto the canonical project.
    from src.default_project import DEFAULT_PROJECT_ID_STR
    repointed_from = None
    if item_id != DEFAULT_PROJECT_ID_STR:
        repointed_from = item_id
        item_id = DEFAULT_PROJECT_ID_STR
    body = await request.json()
    data = body.get("data", {})
    # FEAT-36 — a restored backup can carry an old blob: migrate it too.
    from src.schema_migrations import FutureRevError, migrate_blob
    try:
        data = migrate_blob("asset", data)
    except FutureRevError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    name = body.get("name", "")
    organization = body.get("organization", "")

    from src.backup_common import coerce as _bk_coerce
    from src.routes.projects import _delete_children, _decompose_data
    from src.models import Measure as _Measure
    from sqlalchemy import delete as _delete

    project = await db.get(Project, item_id)
    if project:
        project.name = name or project.name
        project.organization = organization or project.organization
        await _delete_children(db, project.id)
        await _decompose_data(db, project.id, data)
        action = "updated"
    else:
        project = Project(id=item_id, name=name, organization=organization)
        db.add(project)
        await db.flush()
        await _decompose_data(db, project.id, data)
        action = "created"

    dropped: dict = {}
    if isinstance(data, dict) and "measures" in data:
        await db.execute(_delete(_Measure).where(_Measure.project_id == project.id))
        for row in data.get("measures") or []:
            payload = _bk_coerce(_Measure, row, dropped)
            payload["project_id"] = project.id
            db.add(_Measure(**payload))

    from src.audit import log_write
    await log_write(db, None, request, "project.restore", actor="pilot",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await bump_server_rev(db, project.id)
    await db.commit()
    return {"ok": True, "action": action, "dropped_keys": dropped, "repointed_from": repointed_from}


# ── Renewal alerts (SMTP) ───────────────────────────────────────


@router.put("/internal/smtp")
async def set_smtp(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive SMTP config pushed by Pilot. Consumed by src/mailer.py.

    Persists to app_settings (rows smtp.<field>) so the config survives a
    rebuild and is available on the next startup without a Pilot re-push.
    """
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


@router.post("/internal/renewal-run")
async def renewal_run(request: Request, db: AsyncSession = Depends(get_db)):
    """Trigger an immediate renewal check + email digest (bypasses the daily
    cadence gate). Service-token protected — used by the E2E/API tests and for
    manual on-demand sends."""
    _check_service_token(request)
    from src.renewal_scheduler import run_now
    result = await run_now(db)
    # Journal when the run actually created measures or sent the digest —
    # the scheduler tick path (_maybe_run) journals the same way; this
    # on-demand route used to slip through (found while testing the mail
    # functions end-to-end).
    if (result or {}).get("measures_created") or (result or {}).get("sent"):
        from src.audit import log_write
        await log_write(db, None, request, "measure.auto_renewal", actor="pilot",
                        entity_type="measure", details=result)
    await db.commit()
    return result


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
