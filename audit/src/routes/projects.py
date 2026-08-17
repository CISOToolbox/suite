"""Stored audits — blob CRUD + frontend-file import.

Phase-1 persistence: the whole frontend `D` object lives in
`Project.data` (JSONB). No relational decomposition yet — the audit app
mutates `D` and the api layer PUTs the blob (debounced), exactly the
Risk/Vendor phase-0 pattern.

Permission model (same as Asset): the audit base is shared by the
security team. Every authenticated user of the module reads and edits;
delete is admin-only.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import ADMIN_MODULE_ROLES, VIEWER_MODULE_ROLES, auth_enabled, get_current_user, require_admin
from src.database import get_db
from src.models import Project, User
from src.schemas import ProjectCreate, ProjectListItem, ProjectResponse, ProjectUpdate
from src.upload_common import read_json_upload

router = APIRouter(prefix="/api/projects", tags=["projects"])

MAX_BLOB_BYTES = 10 * 1024 * 1024


# ── Helpers ────────────────────────────────────────────────────────

def _user_permissions(user: Optional[User]) -> list[str]:
    if not auth_enabled() or user is None:
        return ["read", "edit", "delete"]
    mrole = getattr(user, "_module_role", "")
    if user.role == "admin" or mrole in ADMIN_MODULE_ROLES:
        return ["read", "edit", "delete"]
    if mrole in VIEWER_MODULE_ROLES:
        return ["read"]
    return ["read", "edit"]


def _require(perm: str, user: Optional[User]) -> None:
    if perm not in _user_permissions(user):
        raise HTTPException(status_code=403, detail=f"Requires '{perm}' permission")


def _sanitize_blob(data: dict) -> dict:
    """Prototype-pollution guard + size ceiling on the stored blob."""
    for k in ("__proto__", "constructor", "prototype"):
        data.pop(k, None)
    if len(json.dumps(data)) > MAX_BLOB_BYTES:
        raise HTTPException(status_code=413, detail="Audit data too large (>10MB)")
    return data


def _meta_fields(data: dict) -> tuple[str, str, str]:
    """(name, organization, audit_date) from the frontend D.meta block.
    Audit's meta = {name, ref, date, auditor, scope, hds} where `name`
    is the audited organization (CT_CONFIG.getSociete)."""
    meta = data.get("meta") or {}
    org = str(meta.get("name") or "")[:255]
    ref = str(meta.get("ref") or "")[:100]
    name = (org + (" — " + ref if ref else ""))[:255] or ref
    date = str(meta.get("date") or "")[:50]
    return name, org, date


# ── CRUD ───────────────────────────────────────────────────────────

@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(
    body: ProjectCreate,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require("edit", user)
    data = _sanitize_blob(body.data or {})
    m_name, m_org, m_date = _meta_fields(data)
    project = Project(
        name=body.name or m_name,
        organization=body.organization or m_org or None,
        audit_date=body.audit_date or m_date or None,
        owner_id=user.id if user else None,
        data=data,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("", response_model=list[ProjectListItem])
async def list_projects(
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    return result.scalars().all()


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Audit not found")
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require("edit", user)
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Audit not found")
    # FEAT-33 stale-tab guard: refuse the whole-blob overwrite when a
    # server-initiated writer bumped server_rev since this tab loaded.
    if body.expected_server_rev is not None and (project.server_rev or 0) > body.expected_server_rev:
        raise HTTPException(status_code=409,
                            detail="Données modifiées côté serveur depuis le chargement (Pilot/scheduler) — rechargez avant une sauvegarde globale.")
    if body.data is not None:
        project.data = _sanitize_blob(body.data)
        m_name, m_org, m_date = _meta_fields(project.data)
        if body.name is None and m_name:
            project.name = m_name
        if body.organization is None and m_org:
            project.organization = m_org
        if body.audit_date is None and m_date:
            project.audit_date = m_date
    if body.name is not None:
        project.name = body.name[:255]
    if body.organization is not None:
        project.organization = body.organization[:255]
    if body.audit_date is not None:
        project.audit_date = body.audit_date[:50]
    from src.audit import log_write
    await log_write(db, user, None,
                    "project.blob_put" if body.data is not None else "project.update",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Audit not found")
    from src.audit import log_write
    await log_write(db, user, None, "project.delete",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.delete(project)
    await db.commit()


@router.post("/{project_id}/duplicate", response_model=ProjectResponse, status_code=201)
async def duplicate_project(
    project_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require("edit", user)
    src = await db.get(Project, project_id)
    if not src:
        raise HTTPException(status_code=404, detail="Audit not found")
    copy = Project(
        name=(src.name + " (copie)")[:255],
        organization=src.organization,
        audit_date=src.audit_date,
        owner_id=user.id if user else None,
        data=src.data,
    )
    db.add(copy)
    await db.commit()
    await db.refresh(copy)
    return copy


# ── Import of a frontend-version file ──────────────────────────────

@router.post("/import", response_model=ProjectResponse, status_code=201)
async def import_project(
    file: UploadFile,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Store a JSON file exported by the frontend (browser-local) Audit
    app as a new audit. Accepts the raw `D` object and the Pilot backup
    wrapper `{"module": ..., "data": [{"id": ..., "data": {...}}]}`.
    Encrypted exports must be opened in the app (which decrypts client-
    side and saves through the normal create path)."""
    _require("edit", user)
    raw = await read_json_upload(file)
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=422, detail="Invalid JSON file (encrypted exports must be opened in the app)")
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="Unexpected JSON structure")
    if parsed.get("module") and isinstance(parsed.get("data"), list) and parsed["data"] and isinstance(parsed["data"][0], dict):
        parsed = parsed["data"][0].get("data") or {}
    if not isinstance(parsed, dict) or "meta" not in parsed:
        raise HTTPException(status_code=422, detail="Not an Audit export file (missing 'meta')")
    # FEAT-36 — refuse future revs, normalize + replay schema migrations.
    from src.schema_migrations import FutureRevError, migrate_blob
    try:
        parsed = migrate_blob("audit", parsed)
    except FutureRevError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    data = _sanitize_blob(parsed)
    m_name, m_org, m_date = _meta_fields(data)
    project = Project(
        name=m_name or (file.filename or "Audit importé")[:255],
        organization=m_org or None,
        audit_date=m_date or None,
        owner_id=user.id if user else None,
        data=data,
    )
    db.add(project)
    await db.flush()
    from src.audit import log_write
    await log_write(db, user, None, "project.import",
                    entity_type="project", entity_id=str(project.id), target=project.name or "")
    await db.commit()
    await db.refresh(project)
    return project
