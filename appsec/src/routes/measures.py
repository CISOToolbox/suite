from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin, require_min_role
from src.database import get_db
from src.models import Measure, User
from src.schemas import MeasureUpdate

router = APIRouter(prefix="/api/measures", tags=["measures"])

# Keep in sync with applications.py / findings.py and Pilot's
# _MODULE_ROLES["appsec"].
_APPSEC_ROLES = ["viewer", "triager", "admin"]


def _to_dict(m: Measure) -> dict:
    return {
        "id": m.id,
        "finding_id": str(m.finding_id) if m.finding_id else None,
        "finding_ids": m.finding_ids or [],
        "title": m.title,
        "description": m.description or "",
        "statut": m.statut,
        "responsable": m.responsable or "",
        "echeance": m.echeance or "",
        "progress_log": m.progress_log or [],
        "created_at": m.created_at,
    }


@router.get("")
async def list_measures(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Measure).order_by(Measure.sort_order))
    return [_to_dict(m) for m in result.scalars().all()]


@router.patch("/{measure_id}")
async def update_measure(
    measure_id: str,
    body: MeasureUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_min_role(user, "triager", _APPSEC_ROLES)
    m = await db.get(Measure, measure_id)
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    if body.title is not None:
        m.title = body.title
    if body.description is not None:
        m.description = body.description
    if body.statut is not None:
        m.statut = body.statut
    if body.responsable is not None:
        m.responsable = body.responsable
    if body.echeance is not None:
        m.echeance = body.echeance
    if body.progress_log is not None:
        m.progress_log = body.progress_log
    await db.commit()
    await db.refresh(m)
    return _to_dict(m)


@router.delete("/{measure_id}", status_code=204)
async def delete_measure(
    measure_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    m = await db.get(Measure, measure_id)
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    await db.delete(m)
    await db.commit()
    return None
