"""Phase 1: scopes + recipients CRUD.

Each user owns scopes; recipients are email-keyed so they don't have
to be Watch users yet. Visibility rule: a scope is visible to its
owner AND to any user whose email is in the recipients list.

Mutations are owner-only. Recipients can read the scope and its target
list (phase 2+) but cannot edit anything.

AUTH_MODE=none: `user is None` means auth is disabled, not "anonymous"
(see THE `None` CONTRACT in src/auth_common.py). There is then no identity
to filter or attribute ownership on, and the caller is admin by contract:
every scope is visible and every owner-only gate passes. Creating a scope
is the one thing that cannot work — `scopes.owner_id` is a NOT NULL FK to
`users.id` — so it answers 503 via `require_identity()` instead of 500.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_identity
from src.database import get_db
from src.models import Scope, ScopeRecipient, User
from src.schemas import (
    ScopeCreate, ScopeUpdate, ScopeResponse,
    ScopeRecipientAdd, ScopeRecipientResponse,
)
from src.audit import log_action

router = APIRouter(prefix="/api/scopes", tags=["scopes"])


# ── Helpers ──────────────────────────────────────────────────────

async def _load_recipients(db: AsyncSession, scope_id: uuid.UUID) -> list[ScopeRecipient]:
    r = await db.execute(
        select(ScopeRecipient).where(ScopeRecipient.scope_id == scope_id).order_by(ScopeRecipient.added_at)
    )
    return list(r.scalars())


async def _owner_email(db: AsyncSession, owner_id: uuid.UUID) -> str:
    r = await db.execute(select(User.email).where(User.id == owner_id))
    return r.scalar_one_or_none() or ""


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


def _scope_to_response(scope: Scope, owner_email: str, recipients: list[ScopeRecipient], user: Optional[User]) -> ScopeResponse:
    return ScopeResponse(
        id=scope.id,
        owner_id=scope.owner_id,
        owner_email=owner_email,
        name=scope.name,
        description=scope.description or "",
        digest_enabled=bool(getattr(scope, "digest_enabled", True)),
        digest_hour=int(getattr(scope, "digest_hour", 7) or 0),
        digest_minute=int(getattr(scope, "digest_minute", 0) or 0),
        digest_timezone=getattr(scope, "digest_timezone", None) or "Europe/Paris",
        digest_severity_min=getattr(scope, "digest_severity_min", None) or "critical",
        digest_include_kev=bool(getattr(scope, "digest_include_kev", True)),
        digest_cvss_min=getattr(scope, "digest_cvss_min", None),
        digest_epss_min=getattr(scope, "digest_epss_min", None),
        threat_digest_enabled=bool(getattr(scope, "threat_digest_enabled", True)),
        threat_digest_frequency=getattr(scope, "threat_digest_frequency", None) or "weekly",
        threat_digest_weekday=int(getattr(scope, "threat_digest_weekday", 0) or 0),
        threat_digest_hour=int(getattr(scope, "threat_digest_hour", 8) or 0),
        threat_digest_minute=int(getattr(scope, "threat_digest_minute", 0) or 0),
        threat_digest_timezone=getattr(scope, "threat_digest_timezone", None) or "Europe/Paris",
        threat_prompt=getattr(scope, "threat_prompt", "") or "",
        threat_search_window_days=int(getattr(scope, "threat_search_window_days", 7) or 7),
        created_at=scope.created_at,
        updated_at=scope.updated_at,
        recipients=[ScopeRecipientResponse.model_validate(rcp) for rcp in recipients],
        is_owner=(user is None or scope.owner_id == user.id),
    )


# ── Routes ───────────────────────────────────────────────────────

@router.get("", response_model=list[ScopeResponse])
async def list_scopes(user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """List every scope visible to the current user (owned + shared).

    With auth disabled there is no identity to filter on and the caller is
    admin: return every scope.
    """
    if user is None:
        scopes = list((await db.execute(select(Scope))).scalars().all())
    else:
        # Owned
        owned = (await db.execute(select(Scope).where(Scope.owner_id == user.id))).scalars().all()
        # Shared via recipient email
        shared_ids = (await db.execute(
            select(ScopeRecipient.scope_id).where(ScopeRecipient.email == user.email.lower())
        )).scalars().all()
        shared = []
        if shared_ids:
            shared = (await db.execute(
                select(Scope).where(Scope.id.in_(shared_ids), Scope.owner_id != user.id)
            )).scalars().all()
        scopes = list(owned) + list(shared)
    my_id = user.id if user else None
    scopes.sort(key=lambda s: (not (s.owner_id == my_id), s.name.lower()))

    out: list[ScopeResponse] = []
    for s in scopes:
        recipients = await _load_recipients(db, s.id)
        owner_email = user.email if (user is not None and s.owner_id == user.id) else await _owner_email(db, s.owner_id)
        out.append(_scope_to_response(s, owner_email, recipients, user))
    return out


@router.post("", response_model=ScopeResponse, status_code=201)
async def create_scope(body: ScopeCreate, request: Request, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # `scopes.owner_id` is a NOT NULL FK: a scope cannot exist without a real
    # owner, so this is one of the rare routes that needs an actual identity.
    owner = require_identity(user)
    now = datetime.now(timezone.utc)
    s = Scope(
        id=uuid.uuid4(),
        owner_id=owner.id,
        name=body.name.strip(),
        description=body.description.strip(),
        digest_enabled=body.digest_enabled,
        digest_hour=body.digest_hour,
        digest_minute=body.digest_minute,
        digest_timezone=(body.digest_timezone or "Europe/Paris").strip(),
        digest_severity_min=body.digest_severity_min,
        digest_include_kev=body.digest_include_kev,
        digest_cvss_min=body.digest_cvss_min,
        digest_epss_min=body.digest_epss_min,
        threat_digest_enabled=body.threat_digest_enabled,
        threat_digest_frequency=body.threat_digest_frequency,
        threat_digest_weekday=body.threat_digest_weekday,
        threat_digest_hour=body.threat_digest_hour,
        threat_digest_minute=body.threat_digest_minute,
        threat_digest_timezone=(body.threat_digest_timezone or "Europe/Paris").strip(),
        threat_prompt=(body.threat_prompt or "").strip(),
        threat_search_window_days=int(body.threat_search_window_days or 7),
        created_at=now,
        updated_at=now,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    await log_action(db, user, request, "scope.create", target=s.name, details=str(s.id))
    await db.commit()
    return _scope_to_response(s, owner.email, [], user)


@router.get("/{scope_id}", response_model=ScopeResponse)
async def get_scope(scope_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scope = (await db.execute(select(Scope).where(Scope.id == scope_id))).scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    if not await _scope_visible(db, scope, user):
        raise HTTPException(status_code=403, detail="not allowed")
    recipients = await _load_recipients(db, scope.id)
    owner_email = user.email if (user is not None and scope.owner_id == user.id) else await _owner_email(db, scope.owner_id)
    return _scope_to_response(scope, owner_email, recipients, user)


@router.patch("/{scope_id}", response_model=ScopeResponse)
async def update_scope(scope_id: uuid.UUID, body: ScopeUpdate, request: Request, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scope = (await db.execute(select(Scope).where(Scope.id == scope_id))).scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    # user is None => auth disabled => admin: the owner-only gate does not apply.
    if user is not None and scope.owner_id != user.id:
        raise HTTPException(status_code=403, detail="only the owner can edit this scope")
    if body.name is not None:
        scope.name = body.name.strip()
    if body.description is not None:
        scope.description = body.description.strip()
    if body.digest_enabled is not None:
        scope.digest_enabled = bool(body.digest_enabled)
    if body.digest_hour is not None:
        scope.digest_hour = int(body.digest_hour)
    if body.digest_minute is not None:
        scope.digest_minute = int(body.digest_minute)
    if body.digest_timezone is not None:
        scope.digest_timezone = body.digest_timezone.strip() or "Europe/Paris"
    if body.digest_severity_min is not None:
        scope.digest_severity_min = body.digest_severity_min
    if body.digest_include_kev is not None:
        scope.digest_include_kev = bool(body.digest_include_kev)
    # Sentinel: client sends -1.0 to clear the gate (set to NULL),
    # any value in [0, 10] sets the floor, omitted/None leaves untouched.
    if body.digest_cvss_min is not None:
        scope.digest_cvss_min = None if body.digest_cvss_min < 0 else float(body.digest_cvss_min)
    if body.digest_epss_min is not None:
        scope.digest_epss_min = None if body.digest_epss_min < 0 else float(body.digest_epss_min)
    # ── Threat digest cadence (M14/M18) ────────────────────────────
    if body.threat_digest_enabled is not None:
        scope.threat_digest_enabled = bool(body.threat_digest_enabled)
    if body.threat_digest_frequency is not None:
        scope.threat_digest_frequency = body.threat_digest_frequency
    if body.threat_digest_weekday is not None:
        scope.threat_digest_weekday = int(body.threat_digest_weekday)
    if body.threat_digest_hour is not None:
        scope.threat_digest_hour = int(body.threat_digest_hour)
    if body.threat_digest_minute is not None:
        scope.threat_digest_minute = int(body.threat_digest_minute)
    if body.threat_digest_timezone is not None:
        scope.threat_digest_timezone = body.threat_digest_timezone.strip() or "Europe/Paris"
    if body.threat_prompt is not None:
        scope.threat_prompt = body.threat_prompt.strip()
    if body.threat_search_window_days is not None:
        scope.threat_search_window_days = int(body.threat_search_window_days)
    scope.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(scope)
    recipients = await _load_recipients(db, scope.id)
    await log_action(db, user, request, "scope.update", target=scope.name, details=str(scope.id))
    await db.commit()
    owner_email = user.email if (user is not None and scope.owner_id == user.id) else await _owner_email(db, scope.owner_id)
    return _scope_to_response(scope, owner_email, recipients, user)


@router.delete("/{scope_id}", status_code=204)
async def delete_scope(scope_id: uuid.UUID, request: Request, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scope = (await db.execute(select(Scope).where(Scope.id == scope_id))).scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    if user is not None and scope.owner_id != user.id:
        raise HTTPException(status_code=403, detail="only the owner can delete this scope")
    name = scope.name
    await db.delete(scope)
    await db.flush()
    await log_action(db, user, request, "scope.delete", target=name, details=str(scope_id))
    await db.commit()
    return None


@router.post("/{scope_id}/recipients", response_model=ScopeRecipientResponse, status_code=201)
async def add_recipient(scope_id: uuid.UUID, body: ScopeRecipientAdd, request: Request, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scope = (await db.execute(select(Scope).where(Scope.id == scope_id))).scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    if user is not None and scope.owner_id != user.id:
        raise HTTPException(status_code=403, detail="only the owner can add recipients")
    # Upsert: if already present, refresh the name snapshot.
    existing = (await db.execute(
        select(ScopeRecipient).where(
            ScopeRecipient.scope_id == scope_id, ScopeRecipient.email == body.email
        )
    )).scalar_one_or_none()
    if existing:
        existing.name = body.name
        await db.commit()
        await db.refresh(existing)
        return ScopeRecipientResponse.model_validate(existing)
    rcp = ScopeRecipient(
        scope_id=scope_id,
        email=body.email,
        name=body.name,
        added_at=datetime.now(timezone.utc),
        # No identity with auth disabled — the row is simply not attributed.
        added_by_email=user.email if user else "",
    )
    db.add(rcp)
    await db.commit()
    await db.refresh(rcp)
    await log_action(db, user, request, "scope.recipient.add", target=scope.name, details=body.email)
    await db.commit()
    return ScopeRecipientResponse.model_validate(rcp)


@router.delete("/{scope_id}/recipients/{email}", status_code=204)
async def remove_recipient(scope_id: uuid.UUID, email: str, request: Request, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scope = (await db.execute(select(Scope).where(Scope.id == scope_id))).scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    if user is not None and scope.owner_id != user.id:
        raise HTTPException(status_code=403, detail="only the owner can remove recipients")
    email_norm = email.strip().lower()
    await db.execute(
        delete(ScopeRecipient).where(
            ScopeRecipient.scope_id == scope_id, ScopeRecipient.email == email_norm
        )
    )
    await db.flush()
    await log_action(db, user, request, "scope.recipient.remove", target=scope.name, details=email_norm)
    await db.commit()
    return None
