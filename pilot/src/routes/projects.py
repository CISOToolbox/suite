"""Projects: group measures into high-level security projects."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_writer
from src.database import get_db
from src.models import MeasureCache, ModuleRegistry, Project, ProjectMeasure, User

router = APIRouter(prefix="/api/projects", tags=["projects"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


# XSS-01: status/priority are interpolated into i18n keys client-side — constrain
# them server-side (same pattern as MeasureUpdate.status in measures.py).
# Values match the frontend selects (Pilot_app.ts). Rows already stored with
# other values are still returned as-is by _project_to_dict (read path is not
# validated), so existing data keeps working; only new writes are constrained.
ProjectStatus = Literal["planned", "in_progress", "completed", "on_hold"]
ProjectPriority = Literal["low", "medium", "high", "critical"]


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    status: ProjectStatus = "planned"
    priority: ProjectPriority = "medium"
    responsible: str | None = None
    start_date: str | None = None
    due_date: str | None = None
    tags: list[str] = []


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: ProjectStatus | None = None
    priority: ProjectPriority | None = None
    responsible: str | None = None
    start_date: str | None = None
    due_date: str | None = None
    completed_date: str | None = None
    tags: list[str] | None = None
    cascade: bool = False



class MeasureAssign(BaseModel):
    measure_ids: list[str]


def _parse_date(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _can_access(p: Project, user: Optional[User]) -> bool:
    if user is None:
        # H-3 fix: only allow when auth is truly disabled
        import os as _os
        return not bool(_os.getenv("JWT_SECRET", ""))
    if user.role == "admin":
        return True
    # Project sharing was removed: a project belongs to its owner, and
    # administrators see everything. The share list it replaced was binary —
    # being on it granted edit, delete AND re-share, with no way to grant less.
    return bool(p.owner_id) and str(p.owner_id) == str(user.id)


def _project_to_dict(p: Project, measures: list[dict] | None = None) -> dict:
    # Une mesure abandonnée ne compte ni comme faite ni comme à faire : la
    # laisser au dénominateur plomberait le % du projet pour toujours.
    actives = [m for m in (measures or [])
               if m.get("status") not in ("cancelled", "annule", "Annulé", "abandonne")]
    total = len(actives)
    completed = sum(1 for m in actives if m.get("status") in ("completed", "Terminé", "termine"))
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description or "",
        "status": p.status,
        "owner_id": str(p.owner_id) if p.owner_id else None,
        "priority": p.priority,
        "responsible": p.responsible or "",
        "start_date": p.start_date.isoformat()[:10] if p.start_date else "",
        "due_date": p.due_date.isoformat()[:10] if p.due_date else "",
        "completed_date": p.completed_date.isoformat()[:10] if p.completed_date else "",
        "tags": p.tags or [],
        "measures_total": total,
        "measures_completed": completed,
        "progress": round(completed / total * 100) if total else 0,
        "measures": measures or [],
        "created_at": p.created_at.isoformat() if p.created_at else "",
    }


async def _get_project_measures(project_id: uuid.UUID, db: AsyncSession) -> list[dict]:
    result = await db.execute(
        select(ProjectMeasure).where(ProjectMeasure.project_id == project_id)
    )
    links = result.scalars().all()
    measure_ids = [l.measure_id for l in links]
    if not measure_ids:
        return []
    # Batch fetch all MeasureCache rows in one query instead of N gets
    mc_result = await db.execute(
        select(MeasureCache).where(MeasureCache.id.in_(measure_ids))
    )
    measures = []
    for mc in mc_result.scalars().all():
        d = mc.data or {}
        measures.append({
            "id": str(mc.id),
            "module": mc.module,
            "source_id": mc.source_id,
            "entity_name": mc.entity_name or "",
            "title": d.get("title", ""),
            "status": d.get("status", ""),
            "assignee": d.get("assignee", ""),
            "due_date": d.get("due_date", ""),
        })
    return measures


@router.get("")
async def list_projects(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.due_date.asc().nullslast(), Project.created_at.desc()))
    projects = result.scalars().all()
    items = []
    for p in projects:
        if not _can_access(p, user):
            continue
        measures = await _get_project_measures(p.id, db)
        items.append(_project_to_dict(p, measures))
    return items


@router.post("", status_code=201)
async def create_project(body: ProjectCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    if not (body.name or "").strip():
        raise HTTPException(status_code=400, detail="Project name is required")
    p = Project(
        name=body.name.strip(), description=body.description, status=body.status,
        priority=body.priority, responsible=body.responsible,
        owner_id=user.id if user else None,
        start_date=_parse_date(body.start_date), due_date=_parse_date(body.due_date),
        tags=body.tags,
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)
    return _project_to_dict(p)


@router.get("/{project_id}")
async def get_project(project_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access(p, user):
        raise HTTPException(status_code=403, detail="Access denied")
    measures = await _get_project_measures(p.id, db)
    return _project_to_dict(p, measures)


@router.put("/{project_id}")
async def update_project(project_id: uuid.UUID, body: ProjectUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access(p, user):
        raise HTTPException(status_code=403, detail="Access denied")

    if body.name is not None:
        p.name = body.name
    if body.description is not None:
        p.description = body.description
    if body.priority is not None:
        p.priority = body.priority
    if body.responsible is not None:
        p.responsible = body.responsible
    if body.start_date is not None:
        p.start_date = _parse_date(body.start_date)
    if body.due_date is not None:
        p.due_date = _parse_date(body.due_date)
    if body.completed_date is not None:
        p.completed_date = _parse_date(body.completed_date)
    if body.tags is not None:
        p.tags = body.tags

    old_status = p.status
    if body.status is not None:
        p.status = body.status
        if body.status == "completed" and not p.completed_date:
            p.completed_date = datetime.now(timezone.utc)

    p.updated_at = datetime.now(timezone.utc)
    await db.commit()

    if body.cascade and body.status and body.status != old_status:
        await _cascade_status(p, body.status, db)

    await db.refresh(p)
    measures = await _get_project_measures(p.id, db)
    return _project_to_dict(p, measures)


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access(p, user):
        raise HTTPException(status_code=403, detail="Access denied")
    # Delete links
    result = await db.execute(select(ProjectMeasure).where(ProjectMeasure.project_id == project_id))
    for link in result.scalars().all():
        await db.delete(link)
    await db.delete(p)
    await db.commit()


@router.post("/{project_id}/measures")
async def assign_measures(project_id: uuid.UUID, body: MeasureAssign, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access(p, user):
        raise HTTPException(status_code=403, detail="Access denied")

    for mid_str in body.measure_ids:
        try:
            mid = uuid.UUID(mid_str)
        except ValueError:
            continue
        mc = await db.get(MeasureCache, mid)
        if not mc:
            continue
        # Check not already linked
        existing = await db.execute(
            select(ProjectMeasure).where(ProjectMeasure.project_id == project_id, ProjectMeasure.measure_id == mid)
        )
        if existing.scalar_one_or_none():
            continue
        db.add(ProjectMeasure(project_id=project_id, measure_id=mid))

    await db.commit()
    measures = await _get_project_measures(p.id, db)
    return _project_to_dict(p, measures)


@router.delete("/{project_id}/measures/{measure_id}")
async def unassign_measure(project_id: uuid.UUID, measure_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    # Its twin assign_measures loads the project and calls _can_access; this
    # one went straight to the link row, so any authenticated user could
    # detach any measure from any remediation project just by knowing the ids.
    p = await db.get(Project, project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access(p, user):
        raise HTTPException(status_code=403, detail="Access denied")
    result = await db.execute(
        select(ProjectMeasure).where(ProjectMeasure.project_id == project_id, ProjectMeasure.measure_id == measure_id)
    )
    link = result.scalar_one_or_none()
    if link:
        await db.delete(link)
        await db.commit()
    return {"ok": True}


async def _cascade_status(project: Project, new_status: str, db: AsyncSession) -> None:
    """Write back status to source modules for all measures in this project."""
    result = await db.execute(
        select(ProjectMeasure).where(ProjectMeasure.project_id == project.id)
    )
    links = result.scalars().all()

    # Load module registry for write-back URLs
    mod_result = await db.execute(select(ModuleRegistry))
    mod_map = {m.id: m for m in mod_result.scalars().all()}

    for link in links:
        mc = await db.get(MeasureCache, link.measure_id)
        if not mc:
            continue
        mod = mod_map.get(mc.module)
        if not mod or not mod.internal_url:
            continue

        # Update local cache
        data = dict(mc.data or {})
        data["status"] = new_status
        mc.data = data
        mc.synced_at = datetime.now(timezone.utc)

        # Write back to source module (shared helper — FEAT-11 DRY)
        from src.routes.measures import write_back_measure
        await write_back_measure(mc, {"status": new_status}, mod, raise_on_error=False)

    await db.commit()
