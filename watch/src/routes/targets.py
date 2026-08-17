"""Phase 2: watch targets — technologies surveyed inside a scope.

Routes nest under /api/scopes/{scope_id}/targets so the scope visibility
rule (owner OR recipient) is enforced before any target call. Only the
scope owner can mutate targets; recipients can list them (digest preview).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import log_action
from src.auth import get_current_user
from src.database import get_db
from src.models import Scope, ScopeRecipient, User, WatchTarget
from src.schemas import (
    WatchTargetCreate, WatchTargetUpdate, WatchTargetResponse,
)
from src.target_validation import validate_target, TargetValidationError
from src.matcher import match_target

router = APIRouter(prefix="/api/scopes", tags=["targets"])


async def _scope_visible(db: AsyncSession, scope: Scope, user: Optional[User]) -> bool:
    if user is None:
        return True  # auth disabled: the caller is admin, everything is visible
    if scope.owner_id == user.id:
        return True
    r = await db.execute(
        select(ScopeRecipient.email).where(
            ScopeRecipient.scope_id == scope.id, ScopeRecipient.email == user.email.lower()
        )
    )
    return r.scalar_one_or_none() is not None


async def _load_scope_for(user: Optional[User], db: AsyncSession, scope_id: uuid.UUID, owner_only: bool = False) -> Scope:
    scope = (await db.execute(select(Scope).where(Scope.id == scope_id))).scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    if owner_only:
        # user is None => auth disabled => admin: the owner-only gate does not apply.
        if user is not None and scope.owner_id != user.id:
            raise HTTPException(status_code=403, detail="only the owner can mutate targets")
    else:
        if not await _scope_visible(db, scope, user):
            raise HTTPException(status_code=403, detail="not allowed")
    return scope


@router.get("/{scope_id}/targets", response_model=list[WatchTargetResponse])
async def list_targets(scope_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await _load_scope_for(user, db, scope_id, owner_only=False)
    rows = (await db.execute(
        select(WatchTarget).where(WatchTarget.scope_id == scope_id).order_by(WatchTarget.kind, WatchTarget.value)
    )).scalars().all()
    return [WatchTargetResponse.model_validate(r) for r in rows]


@router.post("/{scope_id}/targets", response_model=WatchTargetResponse, status_code=201)
async def create_target(
    scope_id: uuid.UUID,
    body: WatchTargetCreate,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scope = await _load_scope_for(user, db, scope_id, owner_only=True)
    try:
        norm_value = validate_target(body.kind, body.value)
    except TargetValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    existing = (await db.execute(
        select(WatchTarget).where(
            WatchTarget.scope_id == scope_id,
            WatchTarget.kind == body.kind,
            WatchTarget.value == norm_value,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="target already exists in this scope")

    now = datetime.now(timezone.utc)
    target = WatchTarget(
        id=uuid.uuid4(),
        scope_id=scope_id,
        kind=body.kind,
        value=norm_value,
        label=(body.label or "").strip(),
        version_constraint=(body.version_constraint or "").strip(),
        notes=(body.notes or "").strip(),
        enabled=bool(body.enabled),
        created_at=now,
        updated_at=now,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    # Retro-match the new target against the most recent ingested alerts so the
    # user sees immediate triage value instead of waiting for the next feed tick.
    try:
        backfilled = await match_target(db, target)
        if backfilled:
            await db.commit()
    except Exception:  # pragma: no cover — defensive, never block target creation
        await db.rollback()
    await log_action(db, user, request, "target.create",
                     target=f"{scope.name} / {body.kind}:{norm_value}",
                     details=str(target.id))
    await db.commit()
    return WatchTargetResponse.model_validate(target)


@router.patch("/{scope_id}/targets/{target_id}", response_model=WatchTargetResponse)
async def update_target(
    scope_id: uuid.UUID,
    target_id: uuid.UUID,
    body: WatchTargetUpdate,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scope = await _load_scope_for(user, db, scope_id, owner_only=True)
    target = (await db.execute(
        select(WatchTarget).where(WatchTarget.id == target_id, WatchTarget.scope_id == scope_id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="target not found")

    # kind/value are immutable: changing them re-keys the target which
    # would orphan any future AlertMatch rows. Use delete+create instead.
    if body.label is not None:
        target.label = body.label.strip()
    if body.version_constraint is not None:
        target.version_constraint = body.version_constraint.strip()
    if body.notes is not None:
        target.notes = body.notes.strip()
    if body.enabled is not None:
        target.enabled = bool(body.enabled)
    target.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(target)
    await log_action(db, user, request, "target.update",
                     target=f"{scope.name} / {target.kind}:{target.value}",
                     details=str(target.id))
    await db.commit()
    return WatchTargetResponse.model_validate(target)


@router.delete("/{scope_id}/targets/{target_id}", status_code=204)
async def remove_target(
    scope_id: uuid.UUID,
    target_id: uuid.UUID,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scope = await _load_scope_for(user, db, scope_id, owner_only=True)
    target = (await db.execute(
        select(WatchTarget).where(WatchTarget.id == target_id, WatchTarget.scope_id == scope_id)
    )).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    label = f"{target.kind}:{target.value}"
    await db.delete(target)
    await db.commit()
    await log_action(db, user, request, "target.delete",
                     target=f"{scope.name} / {label}", details=str(target_id))
    await db.commit()
    return None
