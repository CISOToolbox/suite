from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import ADMIN_MODULE_ROLES, VIEWER_MODULE_ROLES, auth_enabled, get_current_user
from src.database import get_db
from src.models import (
    Application, Measure, Project, ProjectMetadata,
    Review, ReviewEntry, ServiceAccount, SiUser, User,
    RequestedEntitlement,
)
from src.backup_common import row_dict as _bk_row
from src.proof_rules import enforce_proof_evidence
from src.routes.si_users import _validate_url_field
from src.schemas import (
    ProjectCreate, ProjectListItem, ProjectResponse,
    ProjectUpdate, ShareRequest,
)
from src.upload_common import read_json_upload

router = APIRouter(prefix="/api/projects", tags=["projects"])


# ── Helpers ────────────────────────────────────────────────────────

def _user_permissions(project: Project, user: Optional[User]) -> list[str]:
    """Access has a single shared project — no per-user ownership.
    Any authenticated user who passed get_current_user (i.e. has a
    module role) gets full read+edit. Only admin gets delete+share.
    The module role gate in get_current_user already blocks users
    without any role on this module."""
    if not auth_enabled() or user is None:
        return ["read", "edit", "delete", "share"]
    mrole = getattr(user, "_module_role", "")
    if user.role == "admin" or mrole in ADMIN_MODULE_ROLES:
        return ["read", "edit", "delete", "share"]
    if mrole in VIEWER_MODULE_ROLES:
        # viewers (incl. a suite-wide "viewer") are read-only — they can see
        # the users / service accounts / perimeters (the review data) but not
        # mutate them.
        return ["read"]
    # Any other authenticated user with a module role gets read+edit.
    return ["read", "edit"]


def _can(perm: str, project: Project, user: Optional[User]) -> bool:
    return perm in _user_permissions(project, user)


# ── Reconstruct D object ──────────────────────────────────────────

def _si_user_to_dict(u: SiUser) -> dict:
    return {
        "id": u.id, "nom": u.nom or "", "prenom": u.prenom or "",
        "email": u.email or "", "statut": u.statut or "actif",
        "type_compte": u.type_compte or "salarie",
        "fonction": u.fonction or "",
        "equipe": u.equipe or "",
        "date_fin_contrat": u.date_fin_contrat or "",
        "manager_email": u.manager_email or "",
        "politique_validee": u.politique_validee or False,
        "politique_date": u.politique_date or "",
        "politique_justification": u.politique_justification or "",
        "mfa_active": u.mfa_active or False,
        "mfa_date": u.mfa_date or "",
        "mfa_justification": u.mfa_justification or "",
        "sensibilisation": u.sensibilisation or False,
        "sensibilisation_date": u.sensibilisation_date or "",
        "sensibilisation_justification": u.sensibilisation_justification or "",
        "sensibilisation_history": u.sensibilisation_history or {},
        "background_check": u.background_check or False,
        "background_check_date": u.background_check_date or "",
        "background_check_justification": u.background_check_justification or "",
        "background_check_url": u.background_check_url or "",
        "nda_signed": u.nda_signed or False,
        "nda_date": u.nda_date or "",
        "nda_justification": u.nda_justification or "",
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else "",
        "account_enabled": u.account_enabled,
        "sync_source": u.sync_source or "",
    }


def _app_to_dict(a: Application) -> dict:
    return {
        "id": a.id, "nom": a.nom or "", "url": a.url or "",
        "reviewers": a.reviewers or [],
        "frequence_revue": a.frequence_revue or "semestrielle",
        "type": a.type or "application",
        "roles": a.roles or [],
    }


def _entry_to_dict(e: ReviewEntry) -> dict:
    return {
        "id": e.id, "type_compte": e.type_compte or "personnel",
        "email_or_login": e.email_or_login or "",
        "nom": e.nom or "", "prenom": e.prenom or "",
        "roles": e.roles or "", "groups": e.groups or "",
        "si_user_id": e.si_user_id or None,
        "decision": e.decision or "pending",
        "decided_by": e.decided_by or "", "decided_at": e.decided_at or "",
        "notes": e.notes or "",
        "last_login_at": e.last_login_at.isoformat() if e.last_login_at else "",
        "account_enabled": e.account_enabled,
    }


def _review_to_dict(r: Review, entries: list[ReviewEntry]) -> dict:
    return {
        "id": r.id, "application_id": r.application_id or "",
        "status": r.status or "en_cours",
        "started_at": r.started_at or "", "closed_at": r.closed_at or "",
        "closed_by": r.closed_by or "",
        "entries": [_entry_to_dict(e) for e in entries],
    }


def _measure_to_dict(m: Measure) -> dict:
    return {
        "id": m.id, "review_entry_id": m.review_entry_id or "",
        "title": m.title or "", "description": m.description or "",
        "statut": m.statut or "a_faire",
        "responsable": m.responsable or "", "echeance": m.echeance or "",
        # FEAT-30 P1.7 — the progress journal is written by Pilot; it must
        # survive the export/restore round-trip.
        "progress_log": m.progress_log or [],
    }


def _sa_to_dict(sa: ServiceAccount) -> dict:
    return {
        "id": sa.id, "name": sa.name or "", "identifier": sa.identifier or "",
        "platform": sa.platform or "", "application_id": sa.application_id or "",
        "purpose": sa.purpose or "", "secret_storage": sa.secret_storage or "unknown",
        "rotation_policy": sa.rotation_policy or "unknown",
        "last_rotation": sa.last_rotation or "",
        "owners": sa.owners or [],
        "risk_level": sa.risk_level or "medium",
        "notes": sa.notes or "",
    }


async def _reconstruct_data(db: AsyncSession, project_id: uuid.UUID) -> dict:
    meta_result = await db.execute(select(ProjectMetadata).where(ProjectMetadata.project_id == project_id))
    meta = meta_result.scalar_one_or_none()

    users_result = await db.execute(select(SiUser).where(SiUser.project_id == project_id).order_by(SiUser.sort_order))
    si_users = users_result.scalars().all()

    apps_result = await db.execute(select(Application).where(Application.project_id == project_id).order_by(Application.sort_order))
    apps = apps_result.scalars().all()

    reviews_result = await db.execute(select(Review).where(Review.project_id == project_id).order_by(Review.sort_order))
    reviews = reviews_result.scalars().all()

    entries_result = await db.execute(select(ReviewEntry).where(ReviewEntry.project_id == project_id).order_by(ReviewEntry.sort_order))
    all_entries = entries_result.scalars().all()
    entries_by_review: dict[str, list[ReviewEntry]] = {}
    for e in all_entries:
        entries_by_review.setdefault(e.review_id, []).append(e)

    measures_result = await db.execute(select(Measure).where(Measure.project_id == project_id).order_by(Measure.sort_order))
    measures = measures_result.scalars().all()

    sa_result = await db.execute(select(ServiceAccount).where(ServiceAccount.project_id == project_id).order_by(ServiceAccount.sort_order))
    service_accounts = sa_result.scalars().all()

    return {
        "metadata": {
            "organization": meta.organization or "" if meta else "",
            "created": meta.created_date or "" if meta else "",
        },
        "si_users": [_si_user_to_dict(u) for u in si_users],
        "applications": [_app_to_dict(a) for a in apps],
        "reviews": [_review_to_dict(r, entries_by_review.get(r.id, [])) for r in reviews],
        "measures": [_measure_to_dict(m) for m in measures],
        "service_accounts": [_sa_to_dict(sa) for sa in service_accounts],
        # FEAT-30 P1.10 — requested entitlements (FEAT-15 lot 4) travel with
        # the backup. Like asset's measures they are consumed by the Pilot
        # restore path ONLY, never by the blob-PUT decompose (the frontend D
        # does not own them, an autosave must not wipe them). The append-only
        # entitlement_audit journal stays out (immutable, like audit_log).
        "requested_entitlements": [_bk_row(e) for e in (await db.execute(
            select(RequestedEntitlement).where(RequestedEntitlement.project_id == project_id)
        )).scalars().all()],
    }


# ── Decompose D object ────────────────────────────────────────────

async def _delete_children(db: AsyncSession, project_id: uuid.UUID):
    await db.execute(delete(ReviewEntry).where(ReviewEntry.project_id == project_id))
    await db.execute(delete(Review).where(Review.project_id == project_id))
    await db.execute(delete(Measure).where(Measure.project_id == project_id))
    await db.execute(delete(ServiceAccount).where(ServiceAccount.project_id == project_id))
    await db.execute(delete(Application).where(Application.project_id == project_id))
    await db.execute(delete(SiUser).where(SiUser.project_id == project_id))
    await db.execute(delete(ProjectMetadata).where(ProjectMetadata.project_id == project_id))


def _parse_dt(val):
    """ISO string -> aware datetime, or None. Export emits isoformat();
    asyncpg refuses raw strings for DateTime columns."""
    if not val:
        return None
    try:
        from datetime import datetime as _dtt
        return _dtt.fromisoformat(str(val))
    except ValueError:
        return None


def _s(val) -> str:
    if val is None:
        return ""
    return str(val)


async def _decompose_data(db: AsyncSession, project_id: uuid.UUID, data: dict):
    meta = data.get("metadata") or {}
    db.add(ProjectMetadata(
        project_id=project_id,
        organization=meta.get("organization", ""),
        created_date=meta.get("created", ""),
    ))

    _VALID_STATUTS = {"actif", "ancien", "recrutement"}
    _VALID_TYPES = {"salarie", "prestataire", "stagiaire", "alternant"}
    for i, u in enumerate(data.get("si_users") or []):
        statut = _s(u.get("statut", "actif")).lower()
        # Tolerate legacy 'employe' value from older exports.
        if statut == "employe":
            statut = "actif"
        if statut not in _VALID_STATUTS:
            statut = "actif"
        type_compte = _s(u.get("type_compte", "salarie")).lower()
        if type_compte not in _VALID_TYPES:
            type_compte = "salarie"
        _su = SiUser(
            project_id=project_id, id=u.get("id", ""), sort_order=i,
            nom=_s(u.get("nom", "")), prenom=_s(u.get("prenom", "")),
            email=_s(u.get("email", "")), statut=statut,
            type_compte=type_compte,
            fonction=_s(u.get("fonction", "")),
            equipe=_s(u.get("equipe", "")),
            date_fin_contrat=_s(u.get("date_fin_contrat", "")),
            manager_email=_s(u.get("manager_email", "")),
            politique_validee=bool(u.get("politique_validee")),
            politique_date=_s(u.get("politique_date", "")),
            politique_justification=_s(u.get("politique_justification", ""))[:2000],
            mfa_active=bool(u.get("mfa_active")),
            mfa_date=_s(u.get("mfa_date", "")),
            mfa_justification=_s(u.get("mfa_justification", ""))[:2000],
            sensibilisation=bool(u.get("sensibilisation")),
            sensibilisation_date=_s(u.get("sensibilisation_date", "")),
            sensibilisation_justification=_s(u.get("sensibilisation_justification", ""))[:2000],
            background_check=bool(u.get("background_check")),
            background_check_date=_s(u.get("background_check_date", "")),
            background_check_justification=_s(u.get("background_check_justification", ""))[:2000],
            # Same field, same guard as patch_si_user: the blob path used to
            # store it raw, so javascript:/data:/file: reached the DB through
            # autosave while the granular endpoint rejected them.
            background_check_url=_validate_url_field(
                u.get("background_check_url", ""), "background_check_url"),
            nda_signed=bool(u.get("nda_signed")),
            nda_date=_s(u.get("nda_date", "")),
            nda_justification=_s(u.get("nda_justification", ""))[:2000],
            # sync_source is exported by _reconstruct_data but was not rebuilt
            # here, so it fell back to the model default "" — a plain autosave
            # PUT silently cleared the Pilot directory lock for every user,
            # losing the link flag and defeating the 403 in si_users.py.
            sync_source=_s(u.get("sync_source", ""))[:20],
            # FEAT-30 P1.10 — exported but never rebuilt: the PSAT history
            # (never-pruned), the connector-fed last_login_at and
            # account_enabled were destroyed by every restore / blob PUT.
            sensibilisation_history=u.get("sensibilisation_history") or {},
            last_login_at=_parse_dt(u.get("last_login_at")),
            account_enabled=u.get("account_enabled"),
        )
        enforce_proof_evidence(_su)
        db.add(_su)

    _VALID_PERIM_TYPES = {"application", "infrastructure", "physique"}
    for i, a in enumerate(data.get("applications") or []):
        ptype = _s(a.get("type", "application")).lower()
        if ptype not in _VALID_PERIM_TYPES:
            ptype = "application"
        proles = a.get("roles")
        proles = [str(r).strip() for r in proles if str(r).strip()][:200] if isinstance(proles, list) else []
        db.add(Application(
            project_id=project_id, id=a.get("id", ""), sort_order=i,
            nom=_s(a.get("nom", "")), url=_s(a.get("url", "")),
            reviewers=a.get("reviewers") or [],
            frequence_revue=_s(a.get("frequence_revue", "semestrielle")),
            type=ptype, roles=proles,
        ))

    for i, r in enumerate(data.get("reviews") or []):
        db.add(Review(
            project_id=project_id, id=r.get("id", ""), sort_order=i,
            application_id=_s(r.get("application_id", "")),
            status=_s(r.get("status", "en_cours")),
            started_at=_s(r.get("started_at", "")),
            closed_at=_s(r.get("closed_at", "")),
            closed_by=_s(r.get("closed_by", "")),
        ))
        for j, e in enumerate(r.get("entries") or []):
            db.add(ReviewEntry(
                project_id=project_id, review_id=r.get("id", ""), id=e.get("id", ""),
                sort_order=j,
                type_compte=_s(e.get("type_compte", "personnel")),
                email_or_login=_s(e.get("email_or_login", "")),
                nom=_s(e.get("nom", "")), prenom=_s(e.get("prenom", "")),
                roles=_s(e.get("roles", "")), groups=_s(e.get("groups", "")),
                si_user_id=e.get("si_user_id") or None,
                decision=_s(e.get("decision", "pending")),
                decided_by=_s(e.get("decided_by", "")),
                decided_at=_s(e.get("decided_at", "")),
                notes=_s(e.get("notes", "")),
                last_login_at=_parse_dt(e.get("last_login_at")),
                account_enabled=e.get("account_enabled"),
            ))

    for i, m in enumerate(data.get("measures") or []):
        db.add(Measure(
            project_id=project_id, id=m.get("id", ""), sort_order=i,
            review_entry_id=_s(m.get("review_entry_id", "")),
            title=_s(m.get("title", "")), description=_s(m.get("description", "")),
            statut=_s(m.get("statut", "a_faire")),
            responsable=_s(m.get("responsable", "")),
            echeance=_s(m.get("echeance", "")),
            progress_log=m.get("progress_log") or [],
        ))

    for i, sa in enumerate(data.get("service_accounts") or []):
        db.add(ServiceAccount(
            project_id=project_id, id=sa.get("id", ""), sort_order=i,
            name=_s(sa.get("name", "")), identifier=_s(sa.get("identifier", "")),
            platform=_s(sa.get("platform", "")), application_id=_s(sa.get("application_id", "")),
            purpose=_s(sa.get("purpose", "")),
            secret_storage=_s(sa.get("secret_storage", "unknown")),
            rotation_policy=_s(sa.get("rotation_policy", "unknown")),
            last_rotation=_s(sa.get("last_rotation", "")),
            owners=sa.get("owners") or [],
            risk_level=_s(sa.get("risk_level", "medium")),
            notes=_s(sa.get("notes", "")),
        ))


# ── Routes ─────────────────────────────────────────────────────────

@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(body: ProjectCreate, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Access uses a single shared project — block creation if one already exists.
    existing = await db.execute(select(func.count()).select_from(Project))
    if (existing.scalar() or 0) > 0:
        raise HTTPException(status_code=409, detail="A project already exists. Access uses a single shared project.")
    project = Project(name=body.name, organization=body.organization, owner_id=user.id if user else None)
    db.add(project)
    await db.flush()
    if body.data:
        await _decompose_data(db, project.id, body.data)
    await db.commit()
    await db.refresh(project)
    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.get("", response_model=list[ProjectListItem])
async def list_projects(user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Canonical project first (FEAT-30 P1bis) — the boot picks list[0].
    from src.default_project import DEFAULT_PROJECT_ID
    result = await db.execute(select(Project).order_by(
        (Project.id == DEFAULT_PROJECT_ID).desc(), Project.updated_at.desc()))
    projects = result.scalars().all()
    if not auth_enabled() or user is None or user.role == "admin":
        return projects
    return [p for p in projects if _can("read", p, user)]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("read", project, user):
        raise HTTPException(status_code=403, detail="Access denied")
    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: uuid.UUID, body: ProjectUpdate, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    # FEAT-33 stale-tab guard: refuse the whole-blob overwrite when a
    # server-initiated writer bumped server_rev since this tab loaded.
    if body.expected_server_rev is not None and (project.server_rev or 0) > body.expected_server_rev:
        raise HTTPException(status_code=409,
                            detail="Données modifiées côté serveur depuis le chargement (Pilot/scheduler) — rechargez avant une sauvegarde globale.")
    if not _can("edit", project, user):
        raise HTTPException(status_code=403, detail="Access denied")
    if body.name is not None:
        project.name = body.name
    if body.organization is not None:
        project.organization = body.organization
    if body.data is not None:
        await _delete_children(db, project.id)
        await _decompose_data(db, project.id, body.data)
    project.updated_at = datetime.now(timezone.utc)
    from src.audit import log_write
    await log_write(db, user, None,
                    "project.blob_put" if body.data is not None else "project.update",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.commit()
    await db.refresh(project)
    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("delete", project, user):
        raise HTTPException(status_code=403, detail="Access denied")
    from src.audit import log_write
    await log_write(db, user, None, "project.delete",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.delete(project)
    await db.commit()


@router.post("/{project_id}/duplicate", response_model=ProjectResponse, status_code=201)
async def duplicate_project(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    original = await db.get(Project, project_id)
    if not original:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("read", original, user):
        raise HTTPException(status_code=403, detail="Access denied")
    original_data = await _reconstruct_data(db, original.id)
    duplicate = Project(name=original.name + " (copy)", organization=original.organization, owner_id=user.id if user else None)
    db.add(duplicate)
    await db.flush()
    await _decompose_data(db, duplicate.id, original_data)
    await db.commit()
    await db.refresh(duplicate)
    data = await _reconstruct_data(db, duplicate.id)
    return _project_response(duplicate, data)


@router.post("/import", response_model=ProjectResponse, status_code=201)
async def import_project(file: UploadFile, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    import json
    content = await read_json_upload(file, 10 * 1024 * 1024)
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    # FEAT-36 — refuse future revs, normalize + replay schema migrations.
    from src.schema_migrations import FutureRevError, migrate_blob
    try:
        data = migrate_blob("access", data)
    except FutureRevError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    name = ""
    if isinstance(data, dict):
        meta = data.get("metadata", {})
        name = meta.get("organization", "") if isinstance(meta, dict) else ""
    project = Project(name=name, owner_id=user.id if user else None)
    db.add(project)
    await db.flush()
    if isinstance(data, dict):
        await _decompose_data(db, project.id, data)
    from src.audit import log_write
    await log_write(db, user, None, "project.import",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.commit()
    await db.refresh(project)
    data_out = await _reconstruct_data(db, project.id)
    return _project_response(project, data_out)


@router.get("/{project_id}/export")
async def export_project(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("read", project, user):
        raise HTTPException(status_code=403, detail="Access denied")
    data = await _reconstruct_data(db, project.id)
    filename = re.sub(r'[^a-zA-Z0-9_-]', '_', project.name or "export") + "_Access.json"
    return JSONResponse(content=data, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/{project_id}/share", response_model=ProjectResponse)
async def share_project(project_id: uuid.UUID, body: ShareRequest, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can("share", project, user):
        raise HTTPException(status_code=403, detail="No share permission")
    valid = {"read", "edit", "delete", "share"}
    perms = [p for p in body.permissions if p in valid]
    if not perms:
        raise HTTPException(status_code=400, detail="At least one valid permission required")
    result = await db.execute(select(User).where(User.email == body.email))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found with this email")
    shared = list(project.shared_with or [])
    found = False
    for entry in shared:
        if entry.get("user_id") == str(target.id):
            entry["permissions"] = perms
            entry["name"] = target.name
            found = True
            break
    if not found:
        shared.append({"user_id": str(target.id), "email": target.email, "name": target.name, "permissions": perms})
    project.shared_with = shared
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(project)
    data = await _reconstruct_data(db, project.id)
    return _project_response(project, data)


def _project_response(project: Project, data: dict) -> dict:
    return {
        "id": project.id, "name": project.name, "organization": project.organization,
        "owner_id": project.owner_id, "shared_with": project.shared_with or [],
        "created_at": project.created_at, "updated_at": project.updated_at, "server_rev": project.server_rev or 0,
        "data": data,
    }
