from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import Measure, User
from src.routes.auth_helpers import get_project_or_404

router = APIRouter(prefix="/api/projects/{project_id}", tags=["measures"])


@router.get("/measures")
async def list_measures(project_id: uuid.UUID, statut: str = None, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    q = select(Measure).where(Measure.project_id == project_id)
    if statut:
        q = q.where(Measure.statut == statut)
    result = await db.execute(q.order_by(Measure.sort_order))
    return [_to_dict(m) for m in result.scalars().all()]


@router.post("/measures", status_code=201)
async def create_measure(project_id: uuid.UUID, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    existing = await db.execute(select(Measure).where(Measure.project_id == project_id))
    all_measures = existing.scalars().all()
    max_order = await db.scalar(select(func.coalesce(func.max(Measure.sort_order), 0)).where(Measure.project_id == project_id))

    max_num = 0
    for m in all_measures:
        try:
            n = int(re.sub(r'\D', '', m.id) or '0')
            if n > max_num:
                max_num = n
        except ValueError:
            pass

    measure = Measure(
        project_id=project_id, id=body.get("id", f"MES-{max_num + 1:03d}"),
        sort_order=(max_order or 0) + 1,
        review_entry_id=body.get("review_entry_id", ""),
        title=body.get("title", ""), description=body.get("description", ""),
        statut=body.get("statut", "a_faire"),
        responsable=body.get("responsable", ""), echeance=body.get("echeance", ""),
        progress_log=body.get("progress_log", []),
    )
    db.add(measure)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(measure)
    return _to_dict(measure)


@router.patch("/measures/{measure_id}")
async def patch_measure(project_id: uuid.UUID, measure_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    measure = await db.get(Measure, (project_id, measure_id))
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")
    for f in ("title", "description", "statut", "responsable", "echeance"):
        if f in body:
            setattr(measure, f, str(body[f]) if body[f] is not None else "")
    if "progress_log" in body:
        measure.progress_log = body["progress_log"] or []
    measure.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(measure)
    return _to_dict(measure)


@router.delete("/measures/{measure_id}", status_code=204)
async def delete_measure(project_id: uuid.UUID, measure_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    measure = await db.get(Measure, (project_id, measure_id))
    if not measure:
        raise HTTPException(status_code=404, detail="Measure not found")
    await db.delete(measure)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


def _to_dict(m: Measure) -> dict:
    return {
        "id": m.id, "review_entry_id": m.review_entry_id or "",
        "title": m.title, "description": m.description or "",
        "statut": m.statut, "responsable": m.responsable or "",
        "echeance": m.echeance or "",
        "progress_log": m.progress_log or [],
    }
