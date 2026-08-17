"""FEAT-35 — the Notifications bell, served from AppSec.

Suite mode (PILOT_URL set): AppSec is a thin proxy — the caller's prefs
live in Pilot's ``notification_prefs`` (single storage; a change made in
either UI is read back identically from the other). Standalone: the same
payload shape is persisted locally (lang + module_prefs only — the
Pilot-specific deadline-digest fields don't exist without Pilot).

Identity is required (an email recipient) — 503 under AUTH_MODE=none,
per the sentinel contract.
"""
from __future__ import annotations

import os
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.auth_common import require_identity
from src.database import get_db
from src.models import Application, NotificationPrefs, User

router = APIRouter(prefix="/api/me/notification-prefs", tags=["notifications"])

PILOT_URL = os.getenv("PILOT_URL", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


def _suite_mode() -> bool:
    return bool(PILOT_URL and SERVICE_TOKEN)


def _normalize_appsec(raw: dict | None) -> dict:
    from src.findings_notify import APPSEC_PREF_DEFAULTS
    out = dict(APPSEC_PREF_DEFAULTS)
    src = raw or {}
    out["alert_enabled"] = bool(src.get("alert_enabled", out["alert_enabled"]))
    out["weekly_enabled"] = bool(src.get("weekly_enabled", out["weekly_enabled"]))
    for k in ("alert_min_severity", "weekly_min_severity"):
        v = src.get(k, out[k])
        if v not in _VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"{k} must be one of {_VALID_SEVERITIES}")
        out[k] = v
    d = src.get("weekly_day", out["weekly_day"])
    if not isinstance(d, int) or not (0 <= d <= 6):
        raise HTTPException(status_code=422, detail="weekly_day must be 0..6")
    out["weekly_day"] = d
    pref = str(src.get("subject_prefix", out.get("subject_prefix", "[AppSec]")) or "").strip()[:60]
    out["subject_prefix"] = pref or "[AppSec]"
    return out


async def _pilot(method: str, path: str, **kw):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.request(
                method, PILOT_URL.rstrip("/") + path,
                headers={"X-Service-Token": SERVICE_TOKEN}, **kw)
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Pilot unreachable")
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="unknown user in Pilot")
    if not resp.is_success:
        raise HTTPException(status_code=resp.status_code, detail=resp.text[:300])
    return resp.json()


@router.get("")
async def get_prefs(user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    if _suite_mode():
        return await _pilot("GET", "/api/internal/notification-prefs",
                            params={"email": user.email})
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    return {"lang": (p.lang if p else "fr"),
            "module_prefs": {"appsec": _normalize_appsec(
                ((p.module_prefs if p else {}) or {}).get("appsec"))}}


@router.put("")
async def put_prefs(body: dict,
                    user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    if _suite_mode():
        return await _pilot("PUT", "/api/internal/notification-prefs",
                            json={"email": user.email, "prefs": body})
    lang = body.get("lang", "fr")
    if lang not in ("fr", "en"):
        raise HTTPException(status_code=422, detail="lang must be fr|en")
    appsec_block = _normalize_appsec((body.get("module_prefs") or {}).get("appsec"))
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    if p is None:
        p = NotificationPrefs(user_id=user.id)
        db.add(p)
    p.lang = lang
    p.module_prefs = {"appsec": appsec_block}
    await db.commit()
    return {"lang": p.lang, "module_prefs": {"appsec": appsec_block}}


@router.post("/test")
async def send_test(user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    """'Run a test' — suite mode delegates the full multi-module
    orchestration to Pilot (single implementation); standalone runs the
    local AppSec test only."""
    user = require_identity(user)
    if _suite_mode():
        return await _pilot("POST", "/api/internal/notification-test-all",
                            json={"email": user.email})
    from src.findings_notify import (
        APPSEC_PREF_DEFAULTS, resolve_recipient_prefs, send_weekly_for_recipient)
    email = user.email.strip().lower()
    prefs_map = await resolve_recipient_prefs(db, [email])
    prefs = prefs_map.get(email, dict(APPSEC_PREF_DEFAULTS))
    if not (prefs.get("alert_enabled") or prefs.get("weekly_enabled")):
        return {"results": {"appsec": "skipped_disabled"}}
    apps = (await db.execute(
        select(Application).where(Application.enabled.is_(True))
    )).scalars().all()
    mine = [a for a in apps
            if email in [(e or "").strip().lower() for e in (a.notification_emails or [])]]
    status = await send_weekly_for_recipient(db, email, mine or apps, prefs, force=True)
    if status == "failed":
        raise HTTPException(status_code=502,
                            detail="Envoi SMTP en échec — vérifier la configuration SMTP")
    return {"results": {"appsec": status}}
