from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import VALID_MODULES, get_current_user, require_admin
from src.database import get_db
from src.models import ModuleRegistry, NotificationPrefs, User
from src.routes.auth import _ensure_directory_entry
from src.routes.directory import _retire_directory_entry
from src.schemas import UserResponse, UserUpdate

router = APIRouter(prefix="/api/users", tags=["users"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

# Module answers that settle a deletion. `skipped` is a module registered
# without an internal_url: no backend, so no `users` row to hold the person.
# `unsupported` (an image without the delete-user route) is NOT settled: the
# module keeps its row until its image is updated and the deletion retried.
_DELETION_CONFIRMED = ("deleted", "absent", "skipped")


def _other_active_admins(target: User):
    """Admins left besides `target`; one whose deletion is under way can no
    longer sign in, so it does not count."""
    return (select(func.count()).select_from(User)
            .where(User.role == "admin", User.id != target.id,
                   User.deletion_requested_at.is_(None)))


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
    if target.deletion_requested_at is not None:
        raise HTTPException(status_code=409, detail="Refused: this account is being deleted.")
    if body.role is not None:
        if body.role not in ("admin", "user", "viewer", "pending"):
            raise HTTPException(status_code=400, detail="Invalid role")
        # Refuse the write that would leave the suite with no administrator.
        # There is no recovery path from that state through the UI: nobody left
        # can promote anyone, and demoting yourself while sole admin is the
        # easiest way to get there by accident.
        if target.role == "admin" and body.role != "admin":
            remaining = await db.execute(_other_active_admins(target))
            if not remaining.scalar():
                raise HTTPException(
                    status_code=409,
                    detail="Refused: this would leave the suite without an administrator.",
                )
        if target.role == "pending" and body.role != "pending":
            # Approval: the account enters the directory now, not at its
            # first sign-in attempt (see _upsert_user).
            await _ensure_directory_entry(db, target.email, target.name or "")
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

    The Pilot row goes only once every module has confirmed. Until then it
    stays, flagged `deletion_requested_at`: it cannot sign in, modules see
    it inactive, and the address cannot open a new account — otherwise the
    next holder of the address would be matched, by email, to the row a
    silent module kept. Calling this route again retries the modules.

    The first call also detaches the person's directory entry from the
    address (kept, inactive) and drops their digest subscription.

    Objects the person owned are kept everywhere: `owner_id` is ON DELETE SET
    NULL, so an analysis, a project or a Watch scope survives its owner.

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
        remaining = await db.execute(_other_active_admins(target))
        if not remaining.scalar():
            raise HTTPException(
                status_code=409,
                detail="Refused: this would leave the suite without an administrator.",
            )
    if user is not None and target.id == user.id:
        raise HTTPException(status_code=409, detail="Refused: cannot delete your own account.")

    email = target.email
    if target.deletion_requested_at is None:
        # Committed before the modules are called: the account is locked out
        # whatever they answer, and however long they take.
        target.deletion_requested_at = datetime.now(timezone.utc)
        await _retire_directory_entry(db, email)
        await db.execute(delete(NotificationPrefs).where(NotificationPrefs.user_id == target.id))
        await db.commit()
    report = await _delete_user_in_modules(email, db)
    # A module that did not confirm keeps its row: the account stays, pending,
    # rather than claiming a clean deletion.
    failed = sorted(m for m, r in report.items() if r not in _DELETION_CONFIRMED)

    from src.audit import log_write
    await log_write(db, user, None, "user.delete",
                    entity_type="user", entity_id=str(target.id), target=email,
                    details={"modules": report, "pending": failed})
    # By id, not through the loaded object: a concurrent retry may have
    # removed the row meanwhile, which is the outcome asked for, not an error.
    if failed:
        res = await db.execute(update(User).where(User.id == target.id).values(deletion_report=report))
        if not res.rowcount:
            # That other retry got every module to confirm: this attempt's
            # answers are moot.
            failed, report = [], {}
    else:
        await db.execute(delete(User).where(User.id == target.id))
    await db.commit()
    return {"ok": True, "email": email, "modules": report, "failed": failed,
            "pending": bool(failed)}


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
