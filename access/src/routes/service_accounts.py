from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import ServiceAccount, User
from src.routes.auth_helpers import get_project_or_404

router = APIRouter(prefix="/api/projects/{project_id}", tags=["service_accounts"])


def _norm_date_expiration(v) -> str:
    """FEAT-42 — server-side validation: '' or a valid ISO date, else 422."""
    s = str(v or "").strip()
    if not s:
        return ""
    try:
        date.fromisoformat(s)
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="date_expiration must be an ISO date (YYYY-MM-DD) or empty")
    return s


@router.get("/service-accounts")
async def list_service_accounts(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.project_id == project_id).order_by(ServiceAccount.sort_order))
    return [_to_dict(sa) for sa in result.scalars().all()]


@router.post("/service-accounts", status_code=201)
async def create_service_account(project_id: uuid.UUID, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    max_order = await db.scalar(select(func.coalesce(func.max(ServiceAccount.sort_order), 0)).where(ServiceAccount.project_id == project_id))
    sa = ServiceAccount(
        project_id=project_id, id=body.get("id", ""), sort_order=(max_order or 0) + 1,
        name=body.get("name", ""), identifier=body.get("identifier", ""),
        platform=body.get("platform", ""), application_id=body.get("application_id", ""),
        purpose=body.get("purpose", ""), secret_storage=body.get("secret_storage", "unknown"),
        rotation_policy=body.get("rotation_policy", "unknown"),
        last_rotation=body.get("last_rotation", ""),
        date_expiration=_norm_date_expiration(body.get("date_expiration", "")),
        owners=body.get("owners") or [],
        risk_level=body.get("risk_level", "medium"),
        notes=body.get("notes", ""),
    )
    db.add(sa)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(sa)
    return _to_dict(sa)


@router.patch("/service-accounts/{sa_id}")
async def patch_service_account(project_id: uuid.UUID, sa_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    sa = await db.get(ServiceAccount, (project_id, sa_id))
    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found")
    for f in ("name", "identifier", "platform", "application_id", "purpose", "secret_storage", "rotation_policy", "last_rotation", "risk_level", "notes"):
        if f in body:
            setattr(sa, f, str(body[f]) if body[f] is not None else "")
    if "date_expiration" in body:
        sa.date_expiration = _norm_date_expiration(body["date_expiration"])
    if "owners" in body:
        sa.owners = body["owners"] if isinstance(body["owners"], list) else []
    if "sort_order" in body:
        sa.sort_order = int(body["sort_order"])
    sa.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(sa)
    return _to_dict(sa)


@router.delete("/service-accounts/{sa_id}", status_code=204)
async def delete_service_account(project_id: uuid.UUID, sa_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    sa = await db.get(ServiceAccount, (project_id, sa_id))
    if not sa:
        raise HTTPException(status_code=404, detail="Service account not found")
    await db.delete(sa)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


def _to_dict(sa: ServiceAccount) -> dict:
    return {
        "id": sa.id, "name": sa.name or "", "identifier": sa.identifier or "",
        "platform": sa.platform or "", "application_id": sa.application_id or "",
        "purpose": sa.purpose or "", "secret_storage": sa.secret_storage or "unknown",
        "rotation_policy": sa.rotation_policy or "unknown",
        "last_rotation": sa.last_rotation or "",
        "date_expiration": sa.date_expiration or "",
        "owners": sa.owners or [],
        "risk_level": sa.risk_level or "medium",
        "notes": sa.notes or "",
    }
