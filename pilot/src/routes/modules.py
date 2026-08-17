"""Module registry and health checks."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("pilot.modules")
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.database import get_db
from src.models import ModuleRegistry, User
from src.schemas import ModuleInfo

router = APIRouter(prefix="/api/modules", tags=["modules"])

# Default module registry (used if DB is empty)
_DEFAULTS = {
    "risk": {"name": "Risk (EBIOS RM)", "internal_url": os.getenv("RISK_URL", "http://risk-app:8080"), "external_url": os.getenv("RISK_EXTERNAL_URL", "/risk/")},
    "vendor": {"name": "Vendor (TPRM)", "internal_url": os.getenv("VENDOR_URL", "http://vendor-app:8080"), "external_url": os.getenv("VENDOR_EXTERNAL_URL", "/vendor/")},
    "compliance": {"name": "Compliance", "internal_url": os.getenv("COMPLIANCE_URL", "http://compliance-app:8080"), "external_url": os.getenv("COMPLIANCE_EXTERNAL_URL", "/compliance/")},
    "audit": {"name": "Audit (ISO 27001)", "internal_url": os.getenv("AUDIT_URL", "http://audit-app:8080"), "external_url": os.getenv("AUDIT_EXTERNAL_URL", "/audit/")},
    "asset": {"name": "Asset Management", "internal_url": os.getenv("ASSET_URL", "http://asset-app:8080"), "external_url": os.getenv("ASSET_EXTERNAL_URL", "/asset/")},
    "access": {"name": "Access Review", "internal_url": os.getenv("ACCESS_URL", "http://access-app:8080"), "external_url": os.getenv("ACCESS_EXTERNAL_URL", "/access/")},
    "surface": {"name": "Surface (ASM)", "internal_url": os.getenv("SURFACE_URL", "http://surface-app:8080"), "external_url": os.getenv("SURFACE_EXTERNAL_URL", "/surface/")},
    "appsec": {"name": "AppSec (SAST/SCA)", "internal_url": os.getenv("APPSEC_URL", "http://appsec-app:8080"), "external_url": os.getenv("APPSEC_EXTERNAL_URL", "/appsec/")},
    "watch": {"name": "Watch (CTI)", "internal_url": os.getenv("WATCH_URL", "http://watch-app:8080"), "external_url": os.getenv("WATCH_EXTERNAL_URL", "/watch/")},
}

# FEAT-31 — compose the registry from env: PILOT_MODULES="risk,compliance"
# restricts _DEFAULTS to that subset, so client forks compose their suite in
# docker-compose.yml + env without editing this file. The registry prune in
# _ensure_registry() then removes de-listed rows (journaled).
_ENABLED = [m.strip() for m in os.getenv("PILOT_MODULES", "").split(",") if m.strip()]
if _ENABLED:
    _DEFAULTS = {k: v for k, v in _DEFAULTS.items() if k in _ENABLED}


async def _ensure_registry(db: AsyncSession) -> list[ModuleRegistry]:
    result = await db.execute(select(ModuleRegistry).order_by(ModuleRegistry.id))
    modules = result.scalars().all()
    if not modules:
        for mid, info in _DEFAULTS.items():
            m = ModuleRegistry(id=mid, name=info["name"], internal_url=info["internal_url"], external_url=info["external_url"])
            db.add(m)
        await db.commit()
        result = await db.execute(select(ModuleRegistry).order_by(ModuleRegistry.id))
        modules = result.scalars().all()
    else:
        # Sync URLs from env vars and display names from _DEFAULTS (in case they changed)
        changed = False
        existing_ids = {m.id for m in modules}
        for m in modules:
            info = _DEFAULTS.get(m.id)
            if info and (m.internal_url != info["internal_url"] or m.external_url != info["external_url"] or m.name != info["name"]):
                m.internal_url = info["internal_url"]
                m.external_url = info["external_url"]
                m.name = info["name"]
                changed = True
        # Insert missing defaults (e.g. new module added to _DEFAULTS)
        for mid, info in _DEFAULTS.items():
            if mid not in existing_ids:
                db.add(ModuleRegistry(id=mid, name=info["name"], internal_url=info["internal_url"], external_url=info["external_url"]))
                changed = True
        # Remove modules no longer in _DEFAULTS (e.g. scan → appsec rename)
        for m in modules:
            if m.id not in _DEFAULTS:
                # Registry auto-prune destroys a module's registration (and
                # its backup/restore reachability) — journaled (FEAT-30 P3).
                from src.audit import log_write
                await log_write(db, None, None, "module.registry_prune", actor="system",
                                entity_type="module", entity_id=m.id, target=m.name or m.id)
                await db.delete(m)
                changed = True
        if changed:
            await db.commit()
            result = await db.execute(select(ModuleRegistry).order_by(ModuleRegistry.id))
            modules = result.scalars().all()
    return modules


def _menu_payload(modules) -> list[dict]:
    """Public-safe module-switcher entries (FEAT-31): never internal_url.

    Registry membership == deployed, so every row is listed — a module that
    is momentarily unreachable must not vanish from the menu. Pilot itself
    is not a registry row; it is prepended.
    """
    menu = [{"id": "pilot", "name": "Pilot", "url": os.getenv("PILOT_EXTERNAL_URL", "/")}]
    menu += [{"id": m.id, "name": m.name, "url": m.external_url} for m in modules]
    return menu


@router.get("/menu")
async def modules_menu(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Module-switcher entries for the Pilot frontend (FEAT-31). The sibling
    modules get the same payload through GET /api/internal/modules-menu."""
    return _menu_payload(await _ensure_registry(db))


@router.get("", response_model=list[ModuleInfo])
async def list_modules(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    modules = await _ensure_registry(db)
    user_modules = (user.modules if user else None) or list(_DEFAULTS.keys())
    if user and user.role == "admin":
        user_modules = [m.id for m in modules]
    return [m for m in modules if m.id in user_modules]


@router.post("/health-check")
async def health_check(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    modules = await _ensure_registry(db)
    results = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for m in modules:
            if not m.internal_url:
                m.status = "external"
                m.last_health = datetime.now(timezone.utc)
                results[m.id] = "external"
                continue
            health_url = m.internal_url.rstrip("/") + "/api/health"
            try:
                resp = await client.get(health_url)
                ok = resp.status_code == 200
                m.status = "active" if ok else "error"
                if not ok:
                    logger.warning("module %s health %s on %s", m.id, resp.status_code, health_url)
            except Exception as e:
                m.status = "unreachable"
                logger.warning(
                    "module %s unreachable at %s: %s: %s",
                    m.id, health_url, type(e).__name__, e,
                )
            m.last_health = datetime.now(timezone.utc)
            results[m.id] = m.status
    await db.commit()
    return results
