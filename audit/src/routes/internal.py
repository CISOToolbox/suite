"""Internal API endpoints for Pilot integration (audit module).

Blob model: stats and export read `Project.data` directly. Same
service-token guard as every other module (`X-Service-Token`).
"""
from __future__ import annotations

import logging
import os
import secrets
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.models import Measure, Project, User

router = APIRouter(prefix="/api", tags=["internal"])
logger = logging.getLogger("audit-backend")

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

# Statuses of the audit frontend (STATUS_MAP in ISO_Audit_app):
# c=conforme, ncmaj/ncmin=non-conformité, ps=point sensible,
# pp=piste de progrès, na=non applicable.
_CONFORME = {"c"}
_NON_CONFORME = {"ncmaj", "ncmin"}


def _check_service_token(request: Request) -> None:
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    if not token or not secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


def _audit_counts(data: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in (data.get("findings") or {}).values():
        s = (f or {}).get("status") or ""
        if s:
            counts[s] = counts.get(s, 0) + 1
    return counts


def _audit_score(counts: dict[str, int]) -> int | None:
    """Conformity rate over evaluated, applicable controls."""
    evaluated = sum(n for s, n in counts.items() if s != "na")
    if evaluated == 0:
        return None
    conformes = sum(n for s, n in counts.items() if s in _CONFORME)
    return round(conformes / evaluated * 100)


def _normalize_status(s: str) -> str:
    """Audit measure statut → Pilot transverse status."""
    return {"a_faire": "planned", "en_cours": "in_progress", "termine": "completed"}.get(s, s)


def _posture_label(score) -> str:
    if score is None:
        return "N/A"
    if score >= 80:
        return "Bon"
    if score >= 60:
        return "Moyen"
    if score >= 40:
        return "Faible"
    return "Critique"


@router.get("/internal/stats")
async def internal_stats(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    projects = result.scalars().all()

    total_counts: dict[str, int] = {}
    top_items = []
    scores = []
    for p in projects:
        counts = _audit_counts(p.data or {})
        score = _audit_score(counts)
        if score is not None:
            scores.append(score)
        for s, n in counts.items():
            total_counts[s] = total_counts.get(s, 0) + n
        if len(top_items) < 5:
            top_items.append({
                "label": p.name or "(sans nom)",
                "value": f"{score}%" if score is not None else "—",
                "tone": "low" if (score or 0) >= 80 else ("high" if (score or 0) < 60 else "medium"),
            })

    posture_score = round(sum(scores) / len(scores)) if scores else None
    nc_maj = total_counts.get("ncmaj", 0)
    alerts = []
    if nc_maj:
        alerts.append({
            "severity": "high",
            "message": f"{nc_maj} non-conformité(s) majeure(s) ouvertes sur l'ensemble des audits",
        })

    m_rows = (await db.execute(select(Measure))).scalars().all()
    m_completed = sum(1 for m in m_rows if m.statut == "termine")
    m_in_progress = sum(1 for m in m_rows if m.statut == "en_cours")
    m_planned = sum(1 for m in m_rows if m.statut == "a_faire")

    return {
        "entity_count": len(projects),
        "entity_label": "Audits",
        "measures": {
            "total": len(m_rows),
            "completed": m_completed,
            "in_progress": m_in_progress,
            "planned": m_planned,
            "progress_pct": round(m_completed / len(m_rows) * 100) if m_rows else 0,
        },
        "posture": {
            "score": posture_score if posture_score is not None else 0,
            "score_label": _posture_label(posture_score),
        },
        "breakdown": {
            "type": "bar",
            "data": [
                {"label": "Conforme", "value": total_counts.get("c", 0), "tone": "low"},
                {"label": "NC majeure", "value": nc_maj, "tone": "critical"},
                {"label": "NC mineure", "value": total_counts.get("ncmin", 0), "tone": "high"},
                {"label": "Point sensible", "value": total_counts.get("ps", 0), "tone": "medium"},
                {"label": "Piste de progrès", "value": total_counts.get("pp", 0), "tone": "info"},
            ],
        },
        "top_items": top_items,
        "alerts": alerts,
        "compliance_rate": posture_score,
    }


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
async def set_proxy(request: Request):
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


def _validate_proxy_url(url: str) -> None:
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=422, detail="Invalid proxy URL")


# In-memory custom LLM config (pushed by Pilot) — read by ai_proxy_common.
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
    """Receive user ai_enabled / name update from Pilot."""
    _check_service_token(request)
    body = await request.json()
    email = body.get("email", "")
    if not email:
        return {"ok": False, "error": "no email"}
    result = await db.execute(select(User).where(User.email == email))
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


# ── Measures export / write-back (pilot-dashboard-contract) ─────


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

@router.get("/internal/measures")
async def internal_measures(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    result = await db.execute(select(Measure).order_by(Measure.project_id, Measure.sort_order))
    rows = result.scalars().all()
    proj_names = {}
    if rows:
        pres = await db.execute(select(Project.id, Project.name))
        proj_names = {pid: name for pid, name in pres.all()}
    out = []
    for m in rows:
        out.append({
            # Measure ids are per-audit (MES-001 exists in every audit) but
            # Pilot's cache is unique on (module, source_id) — export a
            # globally unique composite id. patch/delete below parse it.
            # FEAT-32 — unified composite: <project8>:<local id> (was <id>@<uuid>).
            # Pilot's sync re-keys existing cache rows so project links survive.
            "source_id": f"{str(m.project_id)[:8]}:{m.id}",
            "entity_id": str(m.project_id),
            "entity_name": proj_names.get(m.project_id, ""),
            "title": m.title,
            "description": m.description or "",
            "status": _normalize_status(m.statut),
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
            "type": "audit_nc",
            "source_module": "audit",
            "progress_log": m.progress_log or [],
        })
    return out


def _measure_query(source_id: str, entity_id: str | None):
    """Resolve a Pilot source_id back to (measure_id, project scope).

    Accepts the FEAT-32 composite "<project8>:<id>", the legacy
    "<id>@<project_uuid>", and a plain id + entity_id query param. The
    project scope is ALWAYS enforced (security review 2026-08-14): the
    short prefix is resolved against the project uuid server-side, and a
    write-back with no scope at all matches nothing rather than the first
    same-named measure of another audit."""
    from sqlalchemy import String as _Str, cast as _cast, false as _false
    if ":" in source_id:
        prefix, _, mid = source_id.partition(":")
        q = select(Measure).where(Measure.id == mid)
        if entity_id:
            return q.where(Measure.project_id == entity_id)
        return q.where(_cast(Measure.project_id, _Str).like(f"{prefix}%"))
    mid, _, pid = source_id.partition("@")
    q = select(Measure).where(Measure.id == mid)
    scope = pid or entity_id
    if not scope:
        return q.where(_false())
    return q.where(Measure.project_id == scope)


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
    """Write-back from Pilot."""
    _check_service_token(request)
    body = await request.json()
    measure = (await db.execute(_measure_query(source_id, entity_id))).scalar_one_or_none()
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
    measure = (await db.execute(_measure_query(source_id, entity_id))).scalar_one_or_none()
    if measure:
        # Pilot write-back is a business write — journaled (FEAT-30 review).
        from src.audit import log_write
        await log_write(db, None, request, "measure.writeback_delete", actor="pilot",
                        entity_type="measure", entity_id=str(source_id))
        await db.delete(measure)
        await bump_server_rev(db, measure.project_id)
    await db.commit()


# ── Pilot backup (blob model + relational measures) ─────────────
# The blob carries the frontend document D; the `measures` table is
# relational (synced with Pilot) and travels alongside it (FEAT-30
# phase 0 audit: it used to be silently excluded from backups).

from src.backup_common import coerce as _bk_coerce, row_dict as _bk_row


@router.get("/internal/export")
async def internal_export_list(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    return [{"id": str(p.id), "name": p.name or "", "organization": p.organization or "",
             "updated_at": str(p.updated_at)} for p in result.scalars().all()]


@router.get("/internal/export/{item_id}")
async def internal_export_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    project = await db.get(Project, item_id)
    if not project:
        raise HTTPException(status_code=404, detail="Not found")
    measures = (await db.execute(
        select(Measure).where(Measure.project_id == project.id).order_by(Measure.sort_order)
    )).scalars().all()
    return {"id": str(project.id), "name": project.name,
            "organization": project.organization,
            "audit_date": project.audit_date,
            "owner_id": str(project.owner_id) if project.owner_id else None,
            "data": project.data or {},
            "measures": [_bk_row(m) for m in measures]}


@router.put("/internal/restore/{item_id}")
async def internal_restore_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Restore blob + measures. The blob goes through the same
    prototype-pollution/size guard as the user-facing PUT. Measures are
    wiped and re-inserted when the payload carries a ``measures`` key
    (legacy backups without it leave the table untouched)."""
    _check_service_token(request)
    from src.routes.projects import _meta_fields, _sanitize_blob
    body = await request.json()
    _raw_data = body.get("data", {}) or {}
    # FEAT-36 — a restored backup can carry an old blob: migrate it too.
    from src.schema_migrations import FutureRevError, migrate_blob
    try:
        _raw_data = migrate_blob("audit", _raw_data)
    except FutureRevError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    data = _sanitize_blob(_raw_data)
    name = body.get("name", "")
    organization = body.get("organization", "")
    dropped: dict = {}

    project = await db.get(Project, item_id)
    if project:
        project.name = name or project.name
        project.organization = organization or project.organization
        project.data = data
        from src.backup_common import restore_root_fields
        from src.models import User as _RootUser
        await restore_root_fields(db, project, body, _RootUser)
        action = "updated"
    else:
        project = Project(id=item_id, name=name, organization=organization, data=data)
        db.add(project)
        await db.flush()
        from src.backup_common import restore_root_fields
        from src.models import User as _RootUser
        await restore_root_fields(db, project, body, _RootUser)
        action = "created"
    # audit_date is derived from the blob (kept in sync with the PUT path)
    try:
        project.audit_date = _meta_fields(data)[2] or None
    except Exception:
        pass

    if "measures" in body:
        from sqlalchemy import delete as _delete
        await db.execute(_delete(Measure).where(Measure.project_id == project.id))
        for row in body.get("measures") or []:
            payload = _bk_coerce(Measure, row, dropped)
            payload["project_id"] = project.id
            db.add(Measure(**payload))

    from src.audit import log_write
    await log_write(db, None, request, "project.restore", actor="pilot",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await bump_server_rev(db, project.id)
    await db.commit()
    return {"ok": True, "action": action, "dropped_keys": dropped}


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
