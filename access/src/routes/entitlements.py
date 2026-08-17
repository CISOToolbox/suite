from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.auth_common import get_module_role
from src.database import get_db
from src.models import (
    Application, EntitlementAudit, RequestedEntitlement, SiUser, User,
)
from src.routes.auth_helpers import get_project_or_404

router = APIRouter(prefix="/api/projects/{project_id}", tags=["entitlements"])

_MAX_CHAIN_DEPTH = 10


def _actor_email(user: Optional[User]) -> str:
    return (getattr(user, "email", "") or "") if user else "system"


async def _users_by_email(db: AsyncSession, project_id: uuid.UUID) -> dict[str, SiUser]:
    res = await db.execute(select(SiUser).where(SiUser.project_id == project_id))
    return {su.email.lower(): su for su in res.scalars().all() if su.email}


def _can_edit(user: Optional[User], target: SiUser, by_email: dict[str, SiUser]) -> bool:
    """Admin, or anyone in the target user's ascending manager chain
    (direct manager, manager's manager, …). No auth = full access."""
    if get_module_role(user) == "admin":
        return True
    actor = (getattr(user, "email", "") or "").strip().lower()
    if not actor:
        return False
    visited: set[str] = set()
    cur: Optional[SiUser] = target
    for _ in range(_MAX_CHAIN_DEPTH):
        mgr = ((cur.manager_email or "").strip().lower()) if cur else ""
        if not mgr or mgr in visited:
            break
        if mgr == actor:
            return True
        visited.add(mgr)
        cur = by_email.get(mgr)
    return False


def _ent_to_dict(e: RequestedEntitlement) -> dict:
    return {
        "id": e.id, "si_user_id": e.si_user_id, "perimetre_id": e.perimetre_id,
        "role": e.role or "", "status": e.status or "demandee",
        "created_by": e.created_by or "", "created_at": e.created_at.isoformat() if e.created_at else "",
        "updated_by": e.updated_by or "", "updated_at": e.updated_at.isoformat() if e.updated_at else "",
    }


def _audit_to_dict(a: EntitlementAudit) -> dict:
    return {
        "id": str(a.id), "si_user_id": a.si_user_id, "entitlement_id": a.entitlement_id or "",
        "action": a.action, "field": a.field or "",
        "old_value": a.old_value or "", "new_value": a.new_value or "",
        "actor": a.actor or "", "at": a.at.isoformat() if a.at else "",
    }


def _audit(db: AsyncSession, project_id, si_user_id, ent_id, action, field, old, new, actor) -> None:
    db.add(EntitlementAudit(
        project_id=project_id, si_user_id=si_user_id, entitlement_id=ent_id,
        action=action, field=field, old_value=str(old or ""), new_value=str(new or ""),
        actor=actor,
    ))


async def _get_user_or_404(db, project_id, si_user_id) -> SiUser:
    su = await db.get(SiUser, (project_id, si_user_id))
    if not su:
        raise HTTPException(status_code=404, detail="SI user not found")
    return su


@router.get("/si-users/{si_user_id}/entitlements")
async def list_entitlements(project_id: uuid.UUID, si_user_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    res = await db.execute(
        select(RequestedEntitlement).where(
            RequestedEntitlement.project_id == project_id,
            RequestedEntitlement.si_user_id == si_user_id,
        ).order_by(RequestedEntitlement.id)
    )
    return [_ent_to_dict(e) for e in res.scalars().all()]


@router.get("/si-users/{si_user_id}/entitlements/audit")
async def list_entitlement_audit(project_id: uuid.UUID, si_user_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    res = await db.execute(
        select(EntitlementAudit).where(
            EntitlementAudit.project_id == project_id,
            EntitlementAudit.si_user_id == si_user_id,
        ).order_by(EntitlementAudit.at.desc())
    )
    return [_audit_to_dict(a) for a in res.scalars().all()]


@router.post("/si-users/{si_user_id}/entitlements", status_code=201)
async def create_entitlement(project_id: uuid.UUID, si_user_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    su = await _get_user_or_404(db, project_id, si_user_id)
    by_email = await _users_by_email(db, project_id)
    if not _can_edit(user, su, by_email):
        raise HTTPException(status_code=403, detail="Seul un admin ou un supérieur hiérarchique peut modifier les habilitations de cet utilisateur")

    perimetre_id = str(body.get("perimetre_id") or "").strip()
    if not perimetre_id:
        raise HTTPException(status_code=422, detail="perimetre_id requis")
    perim = await db.get(Application, (project_id, perimetre_id))
    if not perim:
        raise HTTPException(status_code=422, detail="Périmètre inconnu")
    role = str(body.get("role") or "").strip()[:500]

    existing = await db.execute(select(RequestedEntitlement.id).where(RequestedEntitlement.project_id == project_id))
    max_num = 0
    for (eid,) in existing.all():
        try:
            n = int(re.sub(r"\D", "", eid) or "0")
            max_num = max(max_num, n)
        except ValueError:
            pass
    actor = _actor_email(user)
    ent = RequestedEntitlement(
        project_id=project_id, id=f"ENT-{max_num + 1:03d}", si_user_id=si_user_id,
        perimetre_id=perimetre_id, role=role, status="demandee",
        created_by=actor, updated_by=actor,
    )
    db.add(ent)
    _audit(db, project_id, si_user_id, ent.id, "add", "", "", f"{perimetre_id}:{role}", actor)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(ent)
    return _ent_to_dict(ent)


@router.patch("/si-users/{si_user_id}/entitlements/{ent_id}")
async def patch_entitlement(project_id: uuid.UUID, si_user_id: str, ent_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    su = await _get_user_or_404(db, project_id, si_user_id)
    by_email = await _users_by_email(db, project_id)
    if not _can_edit(user, su, by_email):
        raise HTTPException(status_code=403, detail="Seul un admin ou un supérieur hiérarchique peut modifier les habilitations de cet utilisateur")
    ent = await db.get(RequestedEntitlement, (project_id, ent_id))
    if not ent or ent.si_user_id != si_user_id:
        raise HTTPException(status_code=404, detail="Habilitation introuvable")

    actor = _actor_email(user)
    changed = False
    if "perimetre_id" in body:
        new_p = str(body["perimetre_id"] or "").strip()
        if new_p and new_p != ent.perimetre_id:
            if not await db.get(Application, (project_id, new_p)):
                raise HTTPException(status_code=422, detail="Périmètre inconnu")
            _audit(db, project_id, si_user_id, ent_id, "modify", "perimetre_id", ent.perimetre_id, new_p, actor)
            ent.perimetre_id = new_p; changed = True
    if "role" in body:
        new_r = str(body["role"] or "").strip()[:500]
        if new_r != (ent.role or ""):
            _audit(db, project_id, si_user_id, ent_id, "modify", "role", ent.role, new_r, actor)
            ent.role = new_r; changed = True
    if "status" in body:
        new_s = str(body["status"] or "").strip()[:30]
        if new_s and new_s != ent.status:
            _audit(db, project_id, si_user_id, ent_id, "modify", "status", ent.status, new_s, actor)
            ent.status = new_s; changed = True
    if changed:
        ent.updated_by = actor
        ent.updated_at = datetime.now(timezone.utc)
        project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(ent)
    return _ent_to_dict(ent)


@router.delete("/si-users/{si_user_id}/entitlements/{ent_id}", status_code=204)
async def delete_entitlement(project_id: uuid.UUID, si_user_id: str, ent_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    project = await get_project_or_404(project_id, user, db, require_perm="delete")
    su = await _get_user_or_404(db, project_id, si_user_id)
    by_email = await _users_by_email(db, project_id)
    if not _can_edit(user, su, by_email):
        raise HTTPException(status_code=403, detail="Seul un admin ou un supérieur hiérarchique peut modifier les habilitations de cet utilisateur")
    ent = await db.get(RequestedEntitlement, (project_id, ent_id))
    if not ent or ent.si_user_id != si_user_id:
        raise HTTPException(status_code=404, detail="Habilitation introuvable")
    _audit(db, project_id, si_user_id, ent_id, "remove", "", f"{ent.perimetre_id}:{ent.role}", "", _actor_email(user))
    await db.delete(ent)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
