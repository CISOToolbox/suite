"""Who manages a scope, and who sees it.

A scope is managed by its owner. Deleting the owner's account keeps the scope
with a null owner (`scopes.owner_id` is ON DELETE SET NULL, as in every other
module): a Watch administrator — suite admin or Watch module admin — then
manages it as its owner would, so it is never left with nobody to edit,
re-address or delete it. Recipients keep reading it, as before.

`user is None` means auth is disabled: the caller is admin, every scope is
managed (see THE `None` CONTRACT in src/auth_common.py).
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import false, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import ADMIN_MODULE_ROLES, get_module_role
from src.models import Scope, ScopeRecipient, User


def is_watch_admin(user: Optional[User]) -> bool:
    return user is None or user.role == "admin" or get_module_role(user) in ADMIN_MODULE_ROLES


def manages(scope: Scope, user: Optional[User]) -> bool:
    """Owner rights on `scope`: its owner, or an administrator once it has none."""
    if user is None:
        return True
    if scope.owner_id is not None:
        return scope.owner_id == user.id
    return is_watch_admin(user)


def managed_clause(user: User):
    """SQL counterpart of `manages()` for a real user."""
    ownerless = Scope.owner_id.is_(None) if is_watch_admin(user) else false()
    return or_(Scope.owner_id == user.id, ownerless)


async def visible(db: AsyncSession, scope: Scope, user: Optional[User]) -> bool:
    """Read access: managed, or addressed to the user as a recipient."""
    if user is None or manages(scope, user):
        return True
    r = await db.execute(
        select(ScopeRecipient.email).where(
            ScopeRecipient.scope_id == scope.id, ScopeRecipient.email == user.email.lower()
        )
    )
    return r.scalar_one_or_none() is not None
