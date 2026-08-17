"""Internal API endpoints for Pilot integration."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.models import Application, Measure, Project, RequestedEntitlement, Review, ServiceAccount, SiUser
from src.proof_rules import enforce_proof_evidence

router = APIRouter(prefix="/api", tags=["internal"])
logger = logging.getLogger("access-internal")

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")



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


def _normalize_status(s: str) -> str:
    mapping = {
        "termine": "completed", "Termine": "completed", "Terminé": "completed", "completed": "completed",
        "en_cours": "in_progress", "En cours": "in_progress", "in_progress": "in_progress",
        "a_faire": "planned", "planifie": "planned", "planned": "planned",
    }
    return mapping.get(s, s)


@router.get("/internal/stats")
async def internal_stats(request: Request, db: AsyncSession = Depends(get_db)):
    """Stats v2 envelope — see shared/docs/pilot-dashboard-contract.md"""
    _check_service_token(request)
    from datetime import date as _date

    total_users = await db.scalar(select(func.count()).select_from(SiUser)) or 0
    total_apps = await db.scalar(select(func.count()).select_from(Application)) or 0
    total_reviews_count = await db.scalar(select(func.count()).select_from(Review)) or 0
    active_reviews = await db.scalar(select(func.count()).select_from(Review).where(Review.status == "en_cours")) or 0
    closed_reviews = await db.scalar(select(func.count()).select_from(Review).where(Review.status == "cloturee")) or 0
    planned_reviews = total_reviews_count - active_reviews - closed_reviews

    measures_result = await db.execute(select(Measure))
    all_measures = measures_result.scalars().all()
    total_measures = len(all_measures)
    completed = 0
    in_progress = 0
    planned = 0
    overdue = 0
    today = _date.today().isoformat()
    for m in all_measures:
        st = (m.statut or "").strip()
        if st in ("completed", "termine", "Terminé"):
            completed += 1
        elif st in ("in_progress", "en_cours"):
            in_progress += 1
        else:
            planned += 1
        if m.echeance and m.echeance < today and st not in ("completed", "termine", "Terminé"):
            overdue += 1
    progress_pct = round(completed / total_measures * 100) if total_measures else 0

    posture_score = round(closed_reviews / total_reviews_count * 100) if total_reviews_count else 100

    # Donut: green = closed, gray = in progress, orange = not started
    donut_segments = [
        {"label": "Terminées", "value": closed_reviews, "color": "green"},
        {"label": "En cours", "value": active_reviews, "color": "gray"},
        {"label": "Non commencées", "value": planned_reviews, "color": "orange"},
    ]

    # Apps without any review or with an overdue review.
    _freq_days = {"mensuelle": 31, "trimestrielle": 92, "semestrielle": 183, "annuelle": 365}
    from datetime import timedelta
    # Latest closed review per application in ONE grouped query (was a SELECT
    # per application — an N+1 on a 30s-polled endpoint). closed_at is an ISO
    # date string, so MAX() is the most recent.
    latest_by_app = dict((await db.execute(
        select(Review.application_id, func.max(Review.closed_at))
        .where(Review.status == "cloturee")
        .group_by(Review.application_id)
    )).all())

    # Project only the columns the loop needs — no full Application hydration.
    app_rows = (await db.execute(
        select(Application.id, Application.frequence_revue)
    )).all()
    apps_needing_review = 0
    for app_id, frequence_revue in app_rows:
        last_closed_str = latest_by_app.get(app_id)
        if not last_closed_str:
            apps_needing_review += 1
            continue
        try:
            last_closed = _date.fromisoformat(last_closed_str)
            days = _freq_days.get(frequence_revue, 183)
            if _date.today() > last_closed + timedelta(days=days):
                apps_needing_review += 1
        except (ValueError, TypeError):
            apps_needing_review += 1

    # Service accounts stats
    total_service_accounts = await db.scalar(select(func.count()).select_from(ServiceAccount)) or 0
    sa_rotation_overdue = 0
    if total_service_accounts:
        _rot_days = {"30d": 30, "60d": 60, "90d": 90, "180d": 180, "365d": 365}
        sa_result = await db.execute(select(ServiceAccount))
        for sa in sa_result.scalars().all():
            rot = _rot_days.get(sa.rotation_policy)
            if rot and sa.last_rotation:
                try:
                    last = _date.fromisoformat(sa.last_rotation)
                    if _date.today() > last + timedelta(days=rot):
                        sa_rotation_overdue += 1
                except (ValueError, TypeError):
                    pass
            elif rot and not sa.last_rotation:
                sa_rotation_overdue += 1

    # FEAT-15 Lot 5: identity-referential counters.
    users_by_type = {"salarie": 0, "prestataire": 0, "stagiaire": 0, "alternant": 0}
    contracts_expiring = 0          # date_fin_contrat within the next 30 days
    contracts_expired_active = 0    # contract ended but the user is still 'actif'
    _today_iso = _date.today().isoformat()
    _soon_iso = (_date.today() + timedelta(days=30)).isoformat()
    users_result = await db.execute(select(SiUser))
    for su in users_result.scalars().all():
        users_by_type[su.type_compte] = users_by_type.get(su.type_compte, 0) + 1
        d = (su.date_fin_contrat or "").strip()
        if d:
            if d < _today_iso:
                if (su.statut or "") == "actif":
                    contracts_expired_active += 1
            elif d <= _soon_iso:
                contracts_expiring += 1
    entitlements_total = await db.scalar(select(func.count()).select_from(RequestedEntitlement)) or 0

    alerts = []
    if contracts_expired_active > 0:
        alerts.append({
            "level": "warning",
            "text": f"{contracts_expired_active} contrat(s) échu(s) mais utilisateur encore actif",
            "url": "/access/",
        })
    if contracts_expiring > 0:
        alerts.append({
            "level": "warning",
            "text": f"{contracts_expiring} contrat(s) arrivent à échéance (≤30j)",
            "url": "/access/",
        })
    if apps_needing_review > 0:
        alerts.append({
            "level": "warning",
            "text": f"{apps_needing_review} application(s) sans revue ou avec revue en retard",
            "url": "/access/",
        })
    if overdue > 0:
        alerts.append({
            "level": "warning",
            "text": f"{overdue} mesure(s) en retard",
            "url": "/access/",
        })
    if sa_rotation_overdue > 0:
        alerts.append({
            "level": "warning",
            "text": f"{sa_rotation_overdue} compte(s) de service avec rotation en retard",
            "url": "/access/",
        })

    return {
        "entity_count": total_apps,
        "entity_label": "Applications",
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
            "type": "donut",
            "data": {
                "segments": donut_segments,
            },
        },
        "top_items": [],
        "alerts": alerts,
        # Legacy
        "total_users": total_users,
        "total_applications": total_apps,
        "active_reviews": active_reviews,
        "closed_reviews": closed_reviews,
        "total_measures": total_measures,
        "measures_progress": progress_pct,
        "service_accounts_total": total_service_accounts,
        "service_accounts_rotation_overdue": sa_rotation_overdue,
        # FEAT-15 Lot 5 — identity referential counters
        "users_by_type": users_by_type,
        "contracts_expiring": contracts_expiring,
        "contracts_expired_active": contracts_expired_active,
        "entitlements_total": entitlements_total,
    }


# Access statut → Pilot personnel statut.
_STATUT_TO_PILOT = {"actif": "actif", "ancien": "inactif", "recrutement": "actif"}


@router.get("/internal/referential")
async def internal_referential(request: Request, db: AsyncSession = Depends(get_db)):
    """Expose the Access user referential to Pilot (FEAT-15 Lot 5).

    Aggregates si_users across all projects, deduped by email (last write
    wins), mapped to Pilot's personnel shape. Pilot pulls this on demand
    ('Importer depuis Access' button). Service-token protected.
    """
    _check_service_token(request)
    result = await db.execute(select(SiUser).order_by(SiUser.updated_at))
    by_email: dict[str, dict] = {}
    for su in result.scalars().all():
        email = (su.email or "").strip()
        if not email:
            continue
        by_email[email.lower()] = {
            "nom": su.nom or "",
            "prenom": su.prenom or "",
            "email": email,
            "fonction": su.fonction or "",
            "departement": su.equipe or "",
            "statut": _STATUT_TO_PILOT.get(su.statut, "actif"),
            "manager_email": su.manager_email or "",
        }
    return list(by_email.values())


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
        select(Review).order_by(Review.updated_at.desc()).limit(10)
    )
    for r in recent.scalars().all():
        events.append({
            "date": (r.updated_at or r.created_at).isoformat(),
            "module": "access",
            "type": "review_updated",
            "label": f"Revue {r.id} — {r.status or 'mise à jour'}",
            "url": "/access/",
        })
    return events[:10]


@router.get("/internal/measures")
async def internal_measures(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    result = await db.execute(select(Measure).order_by(Measure.project_id, Measure.sort_order))
    measures = result.scalars().all()
    return [
        {
            "source_id": m.id,
            "entity_id": str(m.project_id),
            "entity_name": m.title,
            "title": m.title,
            "description": m.description or "",
            "status": _normalize_status(m.statut),
            "assignee": m.responsable or "",
            "due_date": m.echeance or "",
            "type": "access_review",
            "source_module": "access",
            "progress_log": m.progress_log or [],
        }
        for m in measures
    ]


async def bump_server_rev(db, project_id) -> None:
    """FEAT-33 — mark a server-initiated write so stale tabs cannot blob-PUT
    over it (see routes/projects.update_project)."""
    from sqlalchemy import update as _upd
    from src.models import Project as _P
    await db.execute(_upd(_P).where(_P.id == project_id).values(server_rev=_P.server_rev + 1))


@router.patch("/internal/measures/{source_id}")
async def patch_measure(source_id: str, request: Request,
                        entity_id: str | None = None,
                        db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    body = await request.json()
    # Measure ids are unique only within a project — scope by entity_id
    # (= project_id, sent by Pilot) to avoid a cross-project MultipleResultsFound.
    query = select(Measure).where(Measure.id == source_id)
    if entity_id:
        query = query.where(Measure.project_id == entity_id)
    measure = (await db.execute(query)).scalar_one_or_none()
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")
    # Transverse Pilot ↔ Access mapping: title → title, description → description
    # (Access schema already uses the canonical names).
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
    import asyncio
    from src.pilot_notify import notify_pilot_measure
    _norm = {"termine": "completed", "en_cours": "in_progress", "a_faire": "planned"}
    asyncio.ensure_future(notify_pilot_measure({
        "source_id": source_id,
        "title": measure.title or "",
        "description": measure.description or "",
        "status": _norm.get(measure.statut, measure.statut or ""),
        "assignee": measure.responsable or "",
        "due_date": measure.echeance or "",
    }))
    return {"ok": True}


@router.delete("/internal/measures/{source_id}", status_code=204)
async def delete_measure_internal(source_id: str, request: Request,
                                  entity_id: str | None = None,
                                  db: AsyncSession = Depends(get_db)):
    """Delete a measure via Pilot write-back (scoped by entity_id = project)."""
    _check_service_token(request)
    query = select(Measure).where(Measure.id == source_id)
    if entity_id:
        query = query.where(Measure.project_id == entity_id)
    measure = (await db.execute(query)).scalar_one_or_none()
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")
    await db.delete(measure)
    # Pilot write-back is a business write — journaled (FEAT-30 review).
    from src.audit import log_write
    await log_write(db, None, request, "measure.writeback_delete", actor="pilot",
                    entity_type="measure", entity_id=str(source_id))
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


_custom_llm = {"endpoint": "", "model": "", "key": "", "label": "Custom LLM"}

@router.put("/internal/ai-custom")
async def set_custom_llm(request: Request):
    _check_service_token(request)
    global _custom_llm
    body = await request.json()
    _custom_llm = {"endpoint": body.get("endpoint", ""), "model": body.get("model", ""), "key": body.get("key", ""), "label": body.get("label", "Custom LLM")}
    _audit_internal_change(request, "ai_custom.set", {
        "endpoint": _redact_url(_custom_llm["endpoint"]) if _custom_llm["endpoint"] else "(cleared)",
        "model": _custom_llm["model"] or "(none)",
        "label": _custom_llm["label"],
        "key_set": bool(_custom_llm["key"]),
    })
    return {"ok": True}


@router.post("/internal/sync-user")
async def sync_user(request: Request, db: AsyncSession = Depends(get_db)):
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

@router.get("/internal/export")
async def internal_export_list(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    projects = result.scalars().all()
    return [{"id": str(p.id), "name": p.name or "", "organization": p.organization or "", "updated_at": str(p.updated_at)} for p in projects]


@router.get("/internal/export/{item_id}")
async def internal_export_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    from src.routes.projects import _reconstruct_data
    project = await db.get(Project, item_id)
    if not project:
        raise HTTPException(status_code=404, detail="Not found")
    data = await _reconstruct_data(db, project.id)
    return {"id": str(project.id), "name": project.name, "organization": project.organization, "owner_id": str(project.owner_id) if project.owner_id else None, "shared_with": project.shared_with or [], "data": data}


@router.put("/internal/restore/{item_id}")
async def internal_restore_item(item_id: str, request: Request, db: AsyncSession = Depends(get_db)):
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
        data = migrate_blob("access", data)
    except FutureRevError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    name = body.get("name", "")
    organization = body.get("organization", "")
    from src.routes.projects import _delete_children, _decompose_data
    project = await db.get(Project, item_id)
    if project:
        project.name = name or project.name
        project.organization = organization or project.organization
        from src.backup_common import restore_root_fields
        from src.models import User as _RootUser
        await restore_root_fields(db, project, body, _RootUser)
        await _delete_children(db, project.id)
        await _decompose_data(db, project.id, data)
        action = "updated"
    else:
        project = Project(id=item_id, name=name, organization=organization)
        db.add(project)
        await db.flush()
        from src.backup_common import restore_root_fields
        from src.models import User as _RootUser
        await restore_root_fields(db, project, body, _RootUser)
        await _decompose_data(db, project.id, data)
        action = "created"

    # Requested entitlements (FEAT-15 lot 4) are restored HERE only — the
    # blob-PUT decompose must never touch them (the frontend D does not own
    # them). Legacy backups without the key leave the table untouched.
    dropped: dict = {}
    if isinstance(data, dict) and "requested_entitlements" in data:
        from sqlalchemy import delete as _delete
        from src.backup_common import coerce as _bk_coerce
        from src.models import RequestedEntitlement as _RE
        await db.execute(_delete(_RE).where(_RE.project_id == project.id))
        for row in data.get("requested_entitlements") or []:
            payload = _bk_coerce(_RE, row, dropped)
            payload["project_id"] = project.id
            db.add(_RE(**payload))

    from src.audit import log_write
    await log_write(db, None, request, "project.restore", actor="pilot",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await bump_server_rev(db, project.id)
    await db.commit()
    return {"ok": True, "action": action, "dropped_keys": dropped, "repointed_from": repointed_from}


# ═══════════════════════════════════════════════════════════════
# Pilot → Access personnel push (webhook)
# ═══════════════════════════════════════════════════════════════

import re as _re


_EMAIL_RE = _re.compile(r"^[^\s@]{1,100}@[^\s@]{1,255}\.[^\s@]{2,50}$")


@router.post("/internal/personnel-sync")
async def personnel_sync(request: Request, db: AsyncSession = Depends(get_db)):
    """Upsert / mark-as-inactive a SiUser across projects in response
    to a personnel change broadcast by Pilot.

    Body:
        {
          "action": "upsert" | "delete",
          "personnel": { nom, prenom, email, fonction, statut, ... },
          "old_email": "..."              # optional — when Pilot update changed the email
          "project_ids": ["uuid", ...]    # optional — limit scope to these projects
                                          # (omit = all projects, backward compat)
        }

    Matches by (old_email → email). For "delete" actions, marks the
    statut to 'ancien' instead of removing the row so historical
    references (reviews, measures) remain intact.
    """
    import logging
    _check_service_token(request)
    body = await request.json()
    action = body.get("action", "upsert")
    if action not in ("upsert", "delete"):
        raise HTTPException(status_code=400, detail="action must be 'upsert' or 'delete'")
    p = body.get("personnel") or {}
    old_email = (body.get("old_email") or "").strip().lower()
    email = (p.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="personnel.email required")
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="personnel.email format invalid")
    if old_email and not _EMAIL_RE.match(old_email):
        raise HTTPException(status_code=400, detail="old_email format invalid")

    # Optional scope: if Pilot supplies project_ids, restrict updates
    # to those. Otherwise apply to all projects (legacy behaviour).
    requested_pids: Optional[set] = None
    if isinstance(body.get("project_ids"), list):
        try:
            requested_pids = {uuid.UUID(x) for x in body["project_ids"] if x}
        except ValueError:
            raise HTTPException(status_code=400, detail="project_ids must be valid UUIDs")

    logger = logging.getLogger("access-backend")

    _STATUT_MAP = {"actif": "actif", "inactif": "ancien"}

    # Find all SiUsers matching this email (possibly old_email)
    candidates_result = await db.execute(
        select(SiUser).where(func.lower(SiUser.email) == email)
    )
    rows = candidates_result.scalars().all()
    if not rows and old_email and old_email != email:
        result2 = await db.execute(
            select(SiUser).where(func.lower(SiUser.email) == old_email)
        )
        rows = result2.scalars().all()

    # Restrict to requested scope when specified
    if requested_pids is not None:
        rows = [su for su in rows if su.project_id in requested_pids]

    touched_projects: set = set()

    if action == "delete":
        for su in rows:
            logger.info(
                "personnel-sync delete: project=%s si_user_id=%s email=%s",
                su.project_id, su.id, su.email,
            )
            su.statut = "ancien"
            su.sync_source = "pilot"
            touched_projects.add(su.project_id)
    else:
        pilot_statut = _STATUT_MAP.get((p.get("statut") or "").lower(), "actif")
        # Cap lengths to the column sizes (see models.py) so a compromised
        # Pilot can't stuff multi-MB strings that would OOM or break DB writes.
        nom_val = str(p.get("nom") or "")[:255]
        prenom_val = str(p.get("prenom") or "")[:255]
        email_val = str(p.get("email") or "")[:255]
        fonction_val = str(p.get("fonction") or "")[:255]
        existing_pids = {su.project_id for su in rows}
        for su in rows:
            # One-directional guard: never let a Pilot push overwrite an
            # identity OWNED by Access (fed by the HR connector or imported).
            # Those flow Access → Pilot only; Pilot must not clobber them back.
            if (su.sync_source or "") in ("hr_generic", "connector"):
                continue
            # Audit trail for email renames (high-sensitivity change)
            if old_email and old_email == (su.email or "").lower() and email != (su.email or "").lower():
                logger.info(
                    "personnel-sync email rename: project=%s si_user_id=%s %s -> %s",
                    su.project_id, su.id, su.email, p.get("email"),
                )
            su.nom = nom_val or su.nom
            su.prenom = prenom_val or su.prenom
            su.email = email_val or su.email
            su.fonction = fonction_val or su.fonction
            su.statut = pilot_statut
            su.sync_source = "pilot"
            touched_projects.add(su.project_id)

        # Load target projects once (scoped when requested) — avoids
        # the previous 2 * N_projects queries in the per-project loop.
        proj_query = select(Project)
        if requested_pids is not None:
            proj_query = proj_query.where(Project.id.in_(requested_pids))
        projects_result = await db.execute(proj_query)
        target_projects = [pr for pr in projects_result.scalars().all() if pr.id not in existing_pids]

        if target_projects:
            target_ids = {pr.id for pr in target_projects}
            # Bulk-fetch (project_id, id, sort_order) once — build
            # per-project max counters in Python.
            all_rows = await db.execute(
                select(SiUser.project_id, SiUser.id, SiUser.sort_order)
                .where(SiUser.project_id.in_(target_ids))
            )
            max_num_by_pid: dict = {pid: 0 for pid in target_ids}
            max_ord_by_pid: dict = {pid: 0 for pid in target_ids}
            for pid, uid, so in all_rows.all():
                try:
                    n = int(_re.sub(r"\D", "", uid or "") or "0")
                    if n > max_num_by_pid[pid]:
                        max_num_by_pid[pid] = n
                except ValueError:
                    pass
                if (so or 0) > max_ord_by_pid[pid]:
                    max_ord_by_pid[pid] = so or 0

            for proj in target_projects:
                max_num_by_pid[proj.id] += 1
                max_ord_by_pid[proj.id] += 1
                db.add(SiUser(
                    project_id=proj.id,
                    id=f"USR-{max_num_by_pid[proj.id]:03d}",
                    sort_order=max_ord_by_pid[proj.id],
                    nom=nom_val,
                    prenom=prenom_val,
                    email=email_val,
                    fonction=fonction_val,
                    statut=pilot_statut,
                    sync_source="pilot",
                ))
                touched_projects.add(proj.id)

    from src.audit import log_write
    await log_write(db, None, request, "personnel.sync", actor="pilot",
                    entity_type="si_user", details={"projects_touched": len(touched_projects)})
    await db.commit()
    return {"ok": True, "action": action, "projects_touched": len(touched_projects)}


def _apply_awareness_trainings(su, trainings: list[dict], today: str) -> None:
    """Merge a PSAT training snapshot into the user's cumulative awareness
    history and recompute the derived ``sensibilisation`` compliance state.

    ``sensibilisation_history`` is cumulative — every campaign ever seen is
    kept, upserted by name (never pruned). Compliance is driven by lateness
    only:

      * non-compliant  ⟺  at least one training is OVERDUE (not completed AND
                          past its due date)
      * compliant       ⟺  no overdue training

    A completed training never counts as overdue (even if it was finished late),
    and an in-progress training whose deadline has not been reached does NOT
    make the user non-compliant. So a user is compliant as long as she is not
    late on anything; she flips to non-compliant the moment an in-progress
    training passes its due date, and back to compliant once she completes it.
    """
    hist = dict(su.sensibilisation_history or {})
    for t in trainings:
        camp = (t.get("campaign") or "").strip()
        if not camp:
            continue
        completed = bool(t.get("completed"))
        h = dict(hist.get(camp) or {})
        h.update({
            "completed": completed,
            "due_date": str(t.get("due_date") or "")[:20],
            "completion_date": str(t.get("completion_date") or "")[:20],
            "statut": "completed" if completed else "in_progress",
            "last_seen": today,
        })
        h.setdefault("first_seen", today)
        hist[camp] = h
    su.sensibilisation_history = hist

    incomplete = [t for t in trainings if not bool(t.get("completed"))]
    overdue = any(bool(t.get("overdue")) for t in incomplete)
    su.sensibilisation = not overdue

    done_dates = [str(t.get("completion_date") or "") for t in trainings
                  if bool(t.get("completed")) and t.get("completion_date")]
    su.sensibilisation_date = (max(done_dates) if done_dates
                               else (su.sensibilisation_date or today))
    n_done = sum(1 for t in trainings if bool(t.get("completed")))
    summary = f"PSAT : {n_done}/{len(trainings)} formation(s) terminée(s)"
    if incomplete:
        summary += f" — {len(incomplete)} en cours"
        if overdue:
            summary += " (en retard)"
    su.sensibilisation_justification = summary
    su.sync_source = "connector"


@router.post("/internal/awareness-sync")
async def awareness_sync(request: Request, db: AsyncSession = Depends(get_db)):
    """Feed the per-user "sensibilisation" compliance from Pilot's Proofpoint
    PSAT connector (FEAT-18 v2 — cumulative history + computed compliance).

    Body (current):
        { "users": [ { "email": str,
                       "trainings": [ { "campaign": str,
                                        "completed": bool,
                                        "due_date": "YYYY-MM-DD",
                                        "completion_date": "YYYY-MM-DD",
                                        "overdue": bool } ] } ] }

    Legacy body ({email, completed, completion_date, justification}) from older
    Pilot builds is still accepted — mapped to a single-training snapshot so a
    version mismatch between Pilot and Access never breaks the sync.

    Matches SiUser by email (case-insensitive, ALL projects), merges each
    training into ``sensibilisation_history`` and recomputes ``sensibilisation``
    (see ``_apply_awareness_trainings``). ``enforce_proof_evidence`` keeps the
    date+justification invariant (both are always set here). Never creates
    users (PSAT is not authoritative for identity). Returns matched/unmatched.
    """
    _check_service_token(request)
    from datetime import date as _date
    today = _date.today().isoformat()
    body = await request.json()
    users = body.get("users")
    if not isinstance(users, list):
        raise HTTPException(status_code=400, detail="users must be a list")

    matched = 0
    unmatched_emails: list[str] = []
    for entry in users:
        if not isinstance(entry, dict):
            continue
        email = (entry.get("email") or "").strip().lower()
        if not email or not _EMAIL_RE.match(email):
            continue
        rows = (await db.execute(
            select(SiUser).where(func.lower(SiUser.email) == email)
        )).scalars().all()
        if not rows:
            unmatched_emails.append(email)
            continue
        trainings = entry.get("trainings")
        if not isinstance(trainings, list):
            # Legacy single-proof payload → wrap as one completed training.
            trainings = [{
                "campaign": "Sensibilisation",
                "completed": bool(entry.get("completed")),
                "completion_date": str(entry.get("completion_date") or ""),
                "due_date": "",
                "overdue": False,
            }]
        for su in rows:
            _apply_awareness_trainings(su, trainings, today)
            enforce_proof_evidence(su)
            matched += 1

    from src.audit import log_write
    await log_write(db, None, request, "awareness.sync", actor="pilot",
                    entity_type="si_user", details={"matched": matched})
    await db.commit()
    return {
        "ok": True,
        "matched": matched,
        "unmatched": len(unmatched_emails),
        "unmatched_emails": unmatched_emails[:50],
    }


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
