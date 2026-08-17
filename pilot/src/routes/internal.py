"""Internal, service-token-only endpoints consumed by the modules.

Why this exists
---------------
Module sessions are stateless JWTs valid for 24h, and a module never asked
Pilot anything about them: `_sync_user_from_jwt` in auth_common recreated the
local user row from the token's claims alone. So deleting or demoting an
account in Pilot changed nothing until the cookie expired — up to a full day of
retained access, with the embedded permissions frozen at mint time. Pilot's own
`_resolve_user` has always refused a token whose user row is gone; the modules
simply had no way to make the same check.

This endpoint is that way. It is reachable only over the container network:
nginx returns 404 for any path containing an `/internal` segment (see
nginx.conf), so the edge never exposes it, and the service token is required on
top of that.

It answers a deliberately narrow question — is this identity still allowed —
and nothing else. No listing, no lookup by anything other than an exact email,
so it cannot be used to enumerate the directory even with the token.
"""
from __future__ import annotations

import os
import secrets as _secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.models import User

router = APIRouter(prefix="/api/internal", tags=["internal"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


def _check_service_token(request: Request) -> None:
    """Fail closed: an unset token means the channel is not configured, not
    that everyone may call it."""
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    provided = request.headers.get("X-Service-Token", "")
    if not provided or not _secrets.compare_digest(provided, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


@router.get("/modules-menu")
async def internal_modules_menu(request: Request, db: AsyncSession = Depends(get_db)):
    """Module-switcher entries served to the sibling modules' same-origin
    proxies (FEAT-31). Public-safe payload only — no internal_url."""
    _check_service_token(request)
    from src.routes.modules import _ensure_registry, _menu_payload
    return _menu_payload(await _ensure_registry(db))


@router.get("/users/status")
async def user_status(
    request: Request,
    email: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Is `email` still an active account, and with which role?

    `active` is what a module should gate on. `pending` is deliberately not
    active: Pilot parks new accounts there until an admin approves them, and a
    module must not let one in ahead of that decision.
    """
    _check_service_token(request)
    normalised = (email or "").strip().lower()
    if not normalised:
        raise HTTPException(status_code=400, detail="email is required")

    result = await db.execute(select(User).where(User.email == normalised))
    user = result.scalar_one_or_none()
    if user is None:
        return {"exists": False, "active": False, "role": "", "modules": []}
    return {
        "exists": True,
        "active": user.role != "pending",
        "role": user.role or "",
        "modules": list(user.modules or []),
    }


# ── FEAT-35 — notification prefs served to modules ──────────────────────────
# AppSec's bell proxies the caller's prefs here (single storage in Pilot),
# and its digest engine bulk-resolves recipients at send time. Service-token
# guarded like every /internal route; identities are matched by email.

@router.get("/notification-prefs")
async def internal_get_prefs(request: Request, email: str,
                             db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    from src.models import NotificationPrefs, User
    from src.routes.notifications import _dict as _prefs_dict
    user = (await db.execute(
        select(User).where(func.lower(User.email) == (email or "").lower())
    )).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="unknown user")
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    return _prefs_dict(p)


@router.put("/notification-prefs")
async def internal_put_prefs(request: Request, db: AsyncSession = Depends(get_db)):
    _check_service_token(request)
    body = await request.json()
    email = (body.get("email") or "").strip()
    from src.models import NotificationPrefs, User
    from src.routes.notifications import PrefsUpdate, _dict as _prefs_dict, \
        normalize_module_prefs, _VALID_SCOPES, _VALID_UPCOMING
    user = (await db.execute(
        select(User).where(func.lower(User.email) == email.lower())
    )).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="unknown user")
    try:
        upd = PrefsUpdate(**(body.get("prefs") or {}))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:300])
    if upd.scope not in _VALID_SCOPES or (upd.scope == "all" and user.role != "admin"):
        raise HTTPException(status_code=403, detail="scope not allowed for this user")
    if upd.upcoming_days not in _VALID_UPCOMING or upd.lang not in ("fr", "en"):
        raise HTTPException(status_code=422, detail="invalid prefs")
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    if p is None:
        p = NotificationPrefs(user_id=user.id)
        db.add(p)
    p.enabled = upd.enabled
    p.day_of_week = upd.day_of_week
    p.upcoming_days = upd.upcoming_days
    p.include_overdue = upd.include_overdue
    p.scope = upd.scope
    p.modules = upd.modules
    p.lang = upd.lang
    p.subject_prefix = upd.subject_prefix.strip() or "[CISO Toolbox]"
    p.module_prefs = normalize_module_prefs(upd.module_prefs)
    await db.commit()
    return _prefs_dict(p)


@router.post("/notification-prefs/lookup")
async def internal_lookup_prefs(request: Request, db: AsyncSession = Depends(get_db)):
    """Bulk email → prefs resolution for module digest engines. Unknown
    emails are simply absent from the response (module applies defaults)."""
    _check_service_token(request)
    body = await request.json()
    emails = [str(e).strip().lower() for e in (body.get("emails") or []) if e]
    if not emails:
        return {}
    from src.models import NotificationPrefs, User
    from src.routes.notifications import _dict as _prefs_dict
    rows = (await db.execute(
        select(User, NotificationPrefs)
        .outerjoin(NotificationPrefs, NotificationPrefs.user_id == User.id)
        .where(func.lower(User.email).in_(emails))
    )).all()
    return {u.email.lower(): _prefs_dict(p) for u, p in rows}


@router.post("/notification-test")
async def internal_notification_test(request: Request, db: AsyncSession = Depends(get_db)):
    """FEAT-35 — a module's 'run a test' triggers Pilot's own deadline-digest
    test for the caller. Respects the user's enabled flag."""
    _check_service_token(request)
    body = await request.json()
    email = (body.get("email") or "").strip()
    from src.models import NotificationPrefs, User
    user = (await db.execute(
        select(User).where(func.lower(User.email) == email.lower())
    )).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="unknown user")
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    if not (p and p.enabled):
        return {"status": "skipped_disabled"}
    from src.deadline_digest import send_digest_for_user
    return {"status": await send_digest_for_user(db, user, p, force=True)}


@router.post("/notification-test-all")
async def internal_notification_test_all(request: Request, db: AsyncSession = Depends(get_db)):
    """FEAT-35 — a module's 'run a test' delegates the full multi-module
    orchestration here, so every bell behaves identically."""
    _check_service_token(request)
    body = await request.json()
    email = (body.get("email") or "").strip()
    from src.models import User
    user = (await db.execute(
        select(User).where(func.lower(User.email) == email.lower())
    )).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="unknown user")
    from src.routes.notifications import run_all_notification_tests
    return {"results": await run_all_notification_tests(db, user)}


@router.post("/notification-subscribers")
async def internal_notification_subscribers(request: Request, db: AsyncSession = Depends(get_db)):
    """FEAT-35 (Surface) — emails of every user whose prefs enable the given
    module's alerts, with their prefs. Surface has no per-asset recipient
    list: subscription IS the user preference."""
    _check_service_token(request)
    body = await request.json()
    module = (body.get("module") or "").strip()
    if module not in ("surface", "appsec"):
        raise HTTPException(status_code=422, detail="module must be surface|appsec")
    from src.models import NotificationPrefs, User
    from src.routes.notifications import _dict as _prefs_dict
    rows = (await db.execute(
        select(User, NotificationPrefs)
        .join(NotificationPrefs, NotificationPrefs.user_id == User.id)
    )).all()
    out = []
    for u, p in rows:
        block = ((p.module_prefs or {}).get(module)) or {}
        if block.get("alert_enabled"):
            out.append({"email": u.email.lower(), "prefs": _prefs_dict(p)})
    return {"subscribers": out}
