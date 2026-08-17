from __future__ import annotations

import os
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import VALID_MODULES, get_current_user, require_admin
from src.database import get_db
from src.models import ModuleRegistry, User
from src.schemas import UserResponse, UserUpdate

router = APIRouter(prefix="/api/users", tags=["users"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


@router.get("", response_model=list[UserResponse])
async def list_users(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(user_id: uuid.UUID, body: UserUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role is not None:
        if body.role not in ("admin", "user", "viewer", "pending"):
            raise HTTPException(status_code=400, detail="Invalid role")
        # Refuse the write that would leave the suite with no administrator.
        # There is no recovery path from that state through the UI: nobody left
        # can promote anyone, and demoting yourself while sole admin is the
        # easiest way to get there by accident.
        if target.role == "admin" and body.role != "admin":
            remaining = await db.execute(
                select(func.count()).select_from(User)
                .where(User.role == "admin", User.id != target.id)
            )
            if not remaining.scalar():
                raise HTTPException(
                    status_code=409,
                    detail="Refused: this would leave the suite without an administrator.",
                )
        target.role = body.role
    if body.modules is not None:
        invalid = set(body.modules) - VALID_MODULES
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid modules: {invalid}")
        target.modules = body.modules
    if body.permissions is not None:
        # `permissions` was copied in verbatim and then overwrote `modules` —
        # one line after `modules` had been checked against VALID_MODULES. So
        # the vetted list was replaced by unvetted keys, and those keys land in
        # the JWT. Admin-only and fail-closed downstream, so this is a
        # misconfiguration risk rather than a bypass, but the asymmetry between
        # the two fields had no reason to exist.
        invalid = set(body.permissions) - VALID_MODULES
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid modules in permissions: {sorted(invalid)}")
        target.permissions = body.permissions
        # Keep the modules list in sync with the (now validated) permission keys,
        # unless this same request also set `modules` explicitly.
        if body.modules is None:
            target.modules = [m for m, r in body.permissions.items() if r]
    if body.ai_enabled is not None:
        target.ai_enabled = body.ai_enabled
        # Push ai_enabled to all modules
        await _sync_user_to_modules(target, db)
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/{user_id}")
async def delete_user(user_id: uuid.UUID, user: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    """Delete an account and its habilitations across the whole suite.

    Each module keeps its own `users` row — that is where the module role
    lives. Deleting only here would leave a role behind in every module, with
    no way to see it from Pilot: exactly the leftovers this route exists to
    prevent. Modules are de-provisioned first, then the local row (its
    notification_prefs and digest_runs follow by CASCADE).

    Objects the person owned are kept everywhere: `owner_id` is ON DELETE SET
    NULL, so an analysis or a project survives its owner.

    NOT a de-provisioning of the identity provider: if the account still
    exists in Entra/Google, signing in re-creates these rows.
    """
    require_admin(user)
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Same guard as the role change: no path back through the UI once the
    # suite has no administrator left.
    if target.role == "admin":
        remaining = await db.execute(
            select(func.count()).select_from(User)
            .where(User.role == "admin", User.id != target.id)
        )
        if not remaining.scalar():
            raise HTTPException(
                status_code=409,
                detail="Refused: this would leave the suite without an administrator.",
            )
    if user is not None and target.id == user.id:
        raise HTTPException(status_code=409, detail="Refused: cannot delete your own account.")

    email = target.email
    report = await _delete_user_in_modules(email, db)

    from src.audit import log_write
    await log_write(db, user, None, "user.delete",
                    entity_type="user", entity_id=str(target.id), target=email,
                    details={"modules": report})
    await db.delete(target)
    await db.commit()
    # A module that did not answer keeps its row: report it rather than
    # claiming a clean deletion.
    failed = sorted(m for m, r in report.items() if r not in ("deleted", "absent"))
    return {"ok": True, "email": email, "modules": report, "failed": failed}


async def _delete_user_in_modules(email: str, db: AsyncSession) -> dict:
    """De-provision `email` in every registered module. Never raises."""
    result = await db.execute(select(ModuleRegistry))
    headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}
    report: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for m in result.scalars().all():
            if not m.internal_url:
                report[m.id] = "skipped"
                continue
            try:
                resp = await client.post(
                    m.internal_url.rstrip("/") + "/api/internal/delete-user",
                    headers=headers, json={"email": email})
                if resp.status_code == 404:
                    # Module still on an image without the route.
                    report[m.id] = "unsupported"
                elif not resp.is_success:
                    report[m.id] = f"HTTP {resp.status_code}"
                else:
                    report[m.id] = "deleted" if resp.json().get("deleted") else "absent"
            except Exception as e:
                report[m.id] = f"error: {str(e)[:40]}"
    return report


async def _sync_user_to_modules(target: User, db: AsyncSession) -> None:
    """Push user ai_enabled (and role) to all modules that have a backend."""
    result = await db.execute(select(ModuleRegistry))
    modules = result.scalars().all()
    headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}

    payload = {
        "id": str(target.id),
        "email": target.email,
        "name": target.name or "",
        "ai_enabled": target.ai_enabled or "false",
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        for m in modules:
            if not m.internal_url:
                continue
            try:
                await client.post(
                    m.internal_url.rstrip("/") + "/api/internal/sync-user",
                    headers=headers,
                    json=payload,
                )
            except Exception:
                pass  # Best effort
