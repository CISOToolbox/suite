"""Asset remediation measures — per-entity REST CRUD (FEAT-22).

Mirrors the Access measures route. `origine` and `auto_key` are
server-owned: a measure created through this public CRUD is always
`manual` with `auto_key=NULL`. Auto-generated measures (origine=echeance)
are created by renewal_scheduler.py, which reuses the id helpers here so
both share one MES-NNN sequence per project.

Measures live OUTSIDE the project blob decompose (projects.py): they are
never wiped by an autosave. See models.Measure for the persistence note.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import Measure, User
from src.routes.auth_helpers import get_project_or_404

# Defensive caps on the client-supplied progress journal (bounded JSONB).
_MAX_LOG_ENTRIES = 500
_MAX_LOG_TEXT = 5000


def _cap_log(log) -> list:
    if not isinstance(log, list):
        return []
    out = []
    for e in log[-_MAX_LOG_ENTRIES:]:
        if isinstance(e, dict):
            if isinstance(e.get("text"), str) and len(e["text"]) > _MAX_LOG_TEXT:
                e = {**e, "text": e["text"][:_MAX_LOG_TEXT]}
            out.append(e)
    return out

router = APIRouter(prefix="/api/projects/{project_id}", tags=["measures"])


# ── id helpers (shared with renewal_scheduler) ─────────────────

async def max_measure_num(db: AsyncSession, project_id) -> int:
    """Highest numeric suffix of the project's MES-NNN ids (0 if none)."""
    rows = await db.execute(select(Measure.id).where(Measure.project_id == project_id))
    mx = 0
    for (mid,) in rows.all():
        try:
            n = int(re.sub(r"\D", "", mid) or "0")
        except ValueError:
            continue
        if n > mx:
            mx = n
    return mx


def measure_id(n: int) -> str:
    return f"MES-{n:03d}"


async def next_measure_id(db: AsyncSession, project_id) -> str:
    return measure_id(await max_measure_num(db, project_id) + 1)


def _to_dict(m: Measure) -> dict:
    return {
        "id": m.id,
        "title": m.title,
        "description": m.description or "",
        "statut": m.statut,
        "responsable": m.responsable or "",
        "echeance": m.echeance or "",
        "progress_log": m.progress_log or [],
        "origine": m.origine or "manual",
        "asset_id": m.asset_id or "",
    }


@router.get("/measures")
async def list_measures(project_id: uuid.UUID, statut: str = None,
                        user: Optional[User] = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    q = select(Measure).where(Measure.project_id == project_id)
    if statut:
        q = q.where(Measure.statut == statut)
    result = await db.execute(q.order_by(Measure.sort_order))
    return [_to_dict(m) for m in result.scalars().all()]


@router.post("/measures", status_code=201)
async def create_measure(project_id: uuid.UUID, body: dict,
                         user: Optional[User] = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    max_order = await db.scalar(
        select(func.coalesce(func.max(Measure.sort_order), 0)).where(Measure.project_id == project_id)
    )
    measure = Measure(
        project_id=project_id,
        id=body.get("id") or await next_measure_id(db, project_id),
        sort_order=(max_order or 0) + 1,
        title=body.get("title", ""),
        description=body.get("description", ""),
        statut=body.get("statut", "a_faire"),
        responsable=body.get("responsable", ""),
        echeance=body.get("echeance", ""),
        progress_log=_cap_log(body.get("progress_log", [])),
        # origine / asset_id / auto_key are server-owned: public creation is
        # always a manual, un-deduped measure.
        origine="manual",
        asset_id="",
        auto_key=None,
    )
    db.add(measure)
    project.updated_at = datetime.now(timezone.utc)
    try:
        await db.commit()
    except IntegrityError:
        # Client supplied an id that already exists in this project.
        await db.rollback()
        raise HTTPException(status_code=409, detail="Measure id already exists")
    await db.refresh(measure)
    return _to_dict(measure)


@router.patch("/measures/{measure_id}")
async def patch_measure(project_id: uuid.UUID, measure_id: str, body: dict,
                        user: Optional[User] = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    measure = await db.get(Measure, (project_id, measure_id))
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")
    for f in ("title", "description", "statut", "responsable", "echeance"):
        if f in body:
            setattr(measure, f, str(body[f]) if body[f] is not None else "")
    if "progress_log" in body:
        measure.progress_log = _cap_log(body["progress_log"] or [])
    # origine / asset_id / auto_key are never client-editable.
    measure.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(measure)
    return _to_dict(measure)


@router.delete("/measures/{measure_id}", status_code=204)
async def delete_measure(project_id: uuid.UUID, measure_id: str,
                         user: Optional[User] = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    measure = await db.get(Measure, (project_id, measure_id))
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")
    await db.delete(measure)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
