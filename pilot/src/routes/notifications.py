"""FEAT-34 — per-user notification preferences + preview send.

The caller only ever touches HIS OWN prefs: the user_id comes from the
session, never from the body. The feature needs a real identity (an
email recipient), so every route goes through require_identity — in
AUTH_MODE=none it answers 503 and the frontend hides the page (§4.4).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_identity
from src.database import get_db
from src.models import NotificationPrefs, User

router = APIRouter(prefix="/api/me/notification-prefs", tags=["notifications"])

_VALID_SCOPES = ("mine", "all")
_VALID_UPCOMING = (7, 14, 30)
_VALID_SEVERITIES = ("low", "medium", "high", "critical")

_APPSEC_DEFAULTS = {"alert_enabled": True, "alert_min_severity": "low",
                    "weekly_enabled": True, "weekly_day": 0,
                    "weekly_min_severity": "low",
                    "subject_prefix": "[AppSec]"}

# Surface (FEAT-35 extension): simpler model — a user just opts in (default
# OFF), picks a severity floor, and receives every alert of the platform.
_SURFACE_DEFAULTS = {"alert_enabled": False, "alert_min_severity": "low",
                     "subject_prefix": "[Surface]"}


def normalize_module_prefs(raw: dict | None) -> dict:
    """Whitelist-validate the per-module preference blocks (FEAT-35).
    Unknown modules/keys are dropped; invalid values raise 422."""
    out: dict = {}
    a = dict(_APPSEC_DEFAULTS)
    src = (raw or {}).get("appsec") or {}
    if not isinstance(src, dict):
        raise HTTPException(status_code=422, detail="module_prefs.appsec must be an object")
    a["alert_enabled"] = bool(src.get("alert_enabled", a["alert_enabled"]))
    a["weekly_enabled"] = bool(src.get("weekly_enabled", a["weekly_enabled"]))
    for k in ("alert_min_severity", "weekly_min_severity"):
        v = src.get(k, a[k])
        if v not in _VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"{k} must be one of {_VALID_SEVERITIES}")
        a[k] = v
    d = src.get("weekly_day", a["weekly_day"])
    if not isinstance(d, int) or not (0 <= d <= 6):
        raise HTTPException(status_code=422, detail="weekly_day must be 0..6")
    a["weekly_day"] = d
    pref = str(src.get("subject_prefix", a["subject_prefix"]) or "").strip()[:60]
    a["subject_prefix"] = pref or "[AppSec]"
    out["appsec"] = a

    sf = dict(_SURFACE_DEFAULTS)
    src_sf = (raw or {}).get("surface") or {}
    if not isinstance(src_sf, dict):
        raise HTTPException(status_code=422, detail="module_prefs.surface must be an object")
    sf["alert_enabled"] = bool(src_sf.get("alert_enabled", sf["alert_enabled"]))
    v = src_sf.get("alert_min_severity", sf["alert_min_severity"])
    if v not in _VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"alert_min_severity must be one of {_VALID_SEVERITIES}")
    sf["alert_min_severity"] = v
    pref = str(src_sf.get("subject_prefix", sf["subject_prefix"]) or "").strip()[:60]
    sf["subject_prefix"] = pref or "[Surface]"
    out["surface"] = sf
    return out


class PrefsUpdate(BaseModel):
    enabled: bool = False
    day_of_week: int = Field(0, ge=0, le=6)
    upcoming_days: int = 14
    include_overdue: bool = True
    scope: str = "mine"
    modules: list[str] = []
    lang: str = "fr"
    subject_prefix: str = Field("[CISO Toolbox]", max_length=60)
    module_prefs: dict = {}


def _dict(p: NotificationPrefs | None) -> dict:
    if p is None:  # opt-in default: everything off
        return {"enabled": False, "day_of_week": 0, "upcoming_days": 14,
                "include_overdue": True, "scope": "mine", "modules": [], "lang": "fr",
                "subject_prefix": "[CISO Toolbox]",
                "module_prefs": normalize_module_prefs(None)}
    return {"enabled": bool(p.enabled), "day_of_week": p.day_of_week,
            "upcoming_days": p.upcoming_days, "include_overdue": bool(p.include_overdue),
            "scope": p.scope, "modules": list(p.modules or []), "lang": p.lang,
            "subject_prefix": p.subject_prefix or "[CISO Toolbox]",
            "module_prefs": normalize_module_prefs(p.module_prefs)}


async def _load(db: AsyncSession, user: User) -> Optional[NotificationPrefs]:
    return (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()


@router.get("")
async def get_prefs(user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    return _dict(await _load(db, user))


@router.put("")
async def put_prefs(body: PrefsUpdate,
                    user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    if body.scope not in _VALID_SCOPES:
        raise HTTPException(status_code=422, detail="scope must be mine|all")
    if body.scope == "all" and user.role != "admin":
        raise HTTPException(status_code=403, detail="scope 'all' is admin-only")
    if body.upcoming_days not in _VALID_UPCOMING:
        raise HTTPException(status_code=422, detail="upcoming_days must be 7|14|30")
    if body.lang not in ("fr", "en"):
        raise HTTPException(status_code=422, detail="lang must be fr|en")

    p = await _load(db, user)
    if p is None:
        p = NotificationPrefs(user_id=user.id)
        db.add(p)
    p.enabled = body.enabled
    p.day_of_week = body.day_of_week
    p.upcoming_days = body.upcoming_days
    p.include_overdue = body.include_overdue
    p.scope = body.scope
    p.modules = body.modules
    p.lang = body.lang
    p.subject_prefix = body.subject_prefix.strip() or "[CISO Toolbox]"
    p.module_prefs = normalize_module_prefs(body.module_prefs)

    from src.audit import log_write
    await log_write(db, user, None, "notification_prefs.update",
                    entity_type="user", entity_id=str(user.id),
                    details={"enabled": body.enabled, "scope": body.scope})
    await db.commit()
    return _dict(p)


def _module_notifs_enabled(block: dict | None, module: str) -> bool:
    b = block or {}
    if module == "appsec":
        return bool(b.get("alert_enabled") or b.get("weekly_enabled"))
    return bool(b.get("alert_enabled"))


async def run_all_notification_tests(db: AsyncSession, user: User) -> dict:
    """One test email per module whose notifications are enabled in the
    user's prefs. Single implementation — every bell (Pilot or module)
    lands here in suite mode."""
    import os
    import httpx
    from sqlalchemy import select as _sel
    from src.models import ModuleRegistry

    p = await _load(db, user)
    full = _dict(p)
    results: dict = {}

    if full.get("enabled"):
        from src.deadline_digest import send_digest_for_user
        prefs_row = p or NotificationPrefs(user_id=user.id)
        results["pilot"] = await send_digest_for_user(db, user, prefs_row, force=True)
    else:
        results["pilot"] = "skipped_disabled"

    mp = full.get("module_prefs") or {}
    for module in ("appsec", "surface"):
        if not _module_notifs_enabled(mp.get(module), module):
            results[module] = "skipped_disabled"
            continue
        mod = (await db.execute(_sel(ModuleRegistry).where(ModuleRegistry.id == module))).scalar_one_or_none()
        if not (mod and mod.internal_url):
            results[module] = "skipped_not_deployed"
            continue
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    mod.internal_url.rstrip("/") + "/api/internal/notification-test",
                    headers={"X-Service-Token": os.getenv("SERVICE_TOKEN", "")},
                    json={"email": user.email})
            results[module] = (resp.json().get("status") if resp.is_success
                               else f"failed (HTTP {resp.status_code})")
        except httpx.HTTPError:
            results[module] = f"failed (unreachable)"
    return results


@router.post("/test")
async def send_test(user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    """'Run a test': one test email per module whose notifications are
    enabled — Pilot's own digest plus every notif-capable module."""
    user = require_identity(user)
    results = await run_all_notification_tests(db, user)
    if all(str(v).startswith("failed") for v in results.values()):
        raise HTTPException(status_code=502, detail="Tous les envois de test ont échoué — vérifier la configuration SMTP")
    return {"results": results}
