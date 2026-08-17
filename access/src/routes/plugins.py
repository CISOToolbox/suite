from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.crypto import decrypt_config, encrypt_config
from src.database import get_db
from src.models import (
    PluginConfig, SyncJob, User,
)
from src.plugins import PLUGIN_REGISTRY
from src.routes.auth_helpers import get_project_or_404

logger = logging.getLogger("access-backend")

router = APIRouter(tags=["plugins"])


# ── Available plugins (no auth needed) ────────────────────────

@router.get("/api/plugins/available")
async def list_available_plugins():
    result = []
    for key, cls in PLUGIN_REGISTRY.items():
        inst = cls()
        result.append({
            "type": key,
            "label": inst.label,
            "label_en": inst.label_en,
            "config_schema": inst.config_schema,
            "setup_guide": inst.setup_guide,
            "setup_guide_en": inst.setup_guide_en,
            "accepts_file": inst.accepts_file,
        })
    return result


# ── Project-scoped routes ─────────────────────────────────────

_prefix = "/api/projects/{project_id}/plugins"
proj_router = APIRouter(prefix=_prefix, tags=["plugins"])


def _mask_config(cfg: dict) -> dict:
    masked = {}
    for k, v in cfg.items():
        if any(s in k.lower() for s in ("secret", "password", "key", "token", "credential")):
            masked[k] = "****" if v else ""
        else:
            masked[k] = v
    return masked


def _to_dict(pc: PluginConfig) -> dict:
    config_masked = {}
    if pc.config_enc:
        try:
            config_masked = _mask_config(decrypt_config(pc.config_enc))
        except Exception:
            config_masked = {}
    plugin_cls = PLUGIN_REGISTRY.get(pc.plugin_type)
    return {
        "id": pc.id,
        "plugin_type": pc.plugin_type,
        "label": pc.label or "",
        "enabled": pc.enabled,
        "accepts_file": bool(getattr(plugin_cls, "accepts_file", False)) if plugin_cls else False,
        "config": config_masked,
        "group_filters": pc.group_filters or [],
        "application_id": pc.application_id or "",
        "schedule": pc.schedule,
        "last_sync_at": pc.last_sync_at.isoformat() if pc.last_sync_at else None,
        "last_sync_status": pc.last_sync_status or "",
    }


@proj_router.get("")
async def list_plugins(project_id: uuid.UUID, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    await get_project_or_404(project_id, user, db)
    result = await db.execute(
        select(PluginConfig).where(PluginConfig.project_id == project_id).order_by(PluginConfig.sort_order)
    )
    return [_to_dict(pc) for pc in result.scalars().all()]


@proj_router.post("", status_code=201)
async def create_plugin(project_id: uuid.UUID, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    project = await get_project_or_404(project_id, user, db)

    plugin_type = body.get("plugin_type", "")
    if plugin_type not in PLUGIN_REGISTRY:
        raise HTTPException(status_code=400, detail=f"Unknown plugin type: {plugin_type}")

    max_order = await db.scalar(
        select(func.coalesce(func.max(PluginConfig.sort_order), 0)).where(PluginConfig.project_id == project_id)
    )
    max_num = 0
    existing = await db.execute(select(PluginConfig).where(PluginConfig.project_id == project_id))
    for pc in existing.scalars().all():
        try:
            n = int(re.sub(r"\D", "", pc.id) or "0")
            if n > max_num:
                max_num = n
        except ValueError:
            pass

    config_data = body.get("config") or {}
    config_enc = encrypt_config(config_data) if config_data else ""

    pc = PluginConfig(
        project_id=project_id,
        id=f"PLG-{max_num + 1:03d}",
        sort_order=(max_order or 0) + 1,
        plugin_type=plugin_type,
        label=body.get("label", ""),
        enabled=body.get("enabled", False),
        config_enc=config_enc,
        group_filters=body.get("group_filters") or [],
        application_id=body.get("application_id", ""),
        schedule=body.get("schedule", "manual"),
    )
    db.add(pc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(pc)
    return _to_dict(pc)


@proj_router.patch("/{plugin_id}")
async def patch_plugin(project_id: uuid.UUID, plugin_id: str, body: dict, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    project = await get_project_or_404(project_id, user, db)
    pc = await db.get(PluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")

    for f in ("label", "application_id", "schedule"):
        if f in body:
            setattr(pc, f, str(body[f]) if body[f] is not None else "")
    if "enabled" in body:
        pc.enabled = bool(body["enabled"])
    if "group_filters" in body:
        pc.group_filters = body["group_filters"] if isinstance(body["group_filters"], list) else []
    if "config" in body and isinstance(body["config"], dict):
        new_config = body["config"]
        # Merge: keep existing values for masked fields
        if pc.config_enc:
            try:
                old_config = decrypt_config(pc.config_enc)
                for k, v in new_config.items():
                    if v == "****" and k in old_config:
                        new_config[k] = old_config[k]
            except Exception:
                pass
        pc.config_enc = encrypt_config(new_config) if new_config else ""
    if "sort_order" in body:
        pc.sort_order = int(body["sort_order"])

    pc.updated_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(pc)
    return _to_dict(pc)


@proj_router.delete("/{plugin_id}", status_code=204)
async def delete_plugin(project_id: uuid.UUID, plugin_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    project = await get_project_or_404(project_id, user, db)
    pc = await db.get(PluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")
    await db.delete(pc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


@proj_router.post("/{plugin_id}/test")
async def test_plugin(project_id: uuid.UUID, plugin_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    _rate_limit(user, "plugin-test")
    await get_project_or_404(project_id, user, db)
    pc = await db.get(PluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")

    cls = PLUGIN_REGISTRY.get(pc.plugin_type)
    if not cls:
        return {"ok": False, "error": f"Plugin type '{pc.plugin_type}' not available", "details": ""}

    config = {}
    if pc.config_enc:
        try:
            config = decrypt_config(pc.config_enc)
        except Exception as e:
            return {"ok": False, "error": _sanitize_plugin_error(e, "Cannot decrypt config"), "details": ""}

    try:
        result = await cls().test_connection(config)
    except Exception as e:
        result = {"ok": False, "error": _sanitize_plugin_error(e, "Connection test failed"), "details": ""}
    return result


# In-memory per-user rate limiter for outbound probing endpoints
# (test, test-config, import-connector, sync). Prevents an authenticated
# user from sweeping the network or locking an AD service account by
# flooding LDAP bind attempts.
_RATE_WINDOW_SEC = 60
_RATE_MAX_CALLS = 10
_RATE_BUCKETS_MAX = 10_000
_RATE_BUCKETS: dict[str, list[float]] = {}


def _rate_limit(user: Optional[User], key: str) -> None:
    """Sliding-window rate limit. Raises 429 when user exceeds
    _RATE_MAX_CALLS calls on `key` in the last _RATE_WINDOW_SEC seconds.

    Bounded memory: stale buckets are pruned opportunistically on each
    call and the dict is capped at _RATE_BUCKETS_MAX entries (oldest
    dropped) so a long-running process never leaks."""
    import time
    if user is None:
        return
    bucket_key = f"{user.email or user.id}:{key}"
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SEC

    if len(_RATE_BUCKETS) > _RATE_BUCKETS_MAX // 2:
        for k in list(_RATE_BUCKETS.keys()):
            ts = _RATE_BUCKETS[k]
            if not ts or ts[-1] < cutoff:
                del _RATE_BUCKETS[k]
    if len(_RATE_BUCKETS) >= _RATE_BUCKETS_MAX and bucket_key not in _RATE_BUCKETS:
        try:
            _RATE_BUCKETS.pop(next(iter(_RATE_BUCKETS)))
        except StopIteration:
            pass

    window = _RATE_BUCKETS.setdefault(bucket_key, [])
    window[:] = [t for t in window if t > cutoff]
    if len(window) >= _RATE_MAX_CALLS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit: max {_RATE_MAX_CALLS} calls per {_RATE_WINDOW_SEC}s on {key}",
        )
    window.append(now)


def _sanitize_plugin_error(exc: Exception, context: str) -> str:
    """Return a generic error message, logging the details server-side.
    LDAP / HTTP exception strings can leak bind DNs, server hostnames,
    and credential fragments — never surface them to the client."""
    import logging
    logging.getLogger("access-backend").exception("%s: %s", context, exc)
    return f"{context} — check server logs for details"


@router.post("/api/projects/{project_id}/plugins/test-config")
async def test_plugin_config(project_id: uuid.UUID, request: Request, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Test a plugin config from the UI form WITHOUT saving to DB first.
    Accepts the same body shape as create/patch: {plugin_type, config}.

    Admin-only + rate-limited to prevent abuse as an SSRF probe:
    this endpoint accepts an arbitrary URL/host in `config` and opens
    an outbound connection to it, so it must be restricted.
    """
    require_admin(user)
    _rate_limit(user, "plugin-test-config")
    await get_project_or_404(project_id, user, db)
    body = await request.json()
    plugin_type = body.get("plugin_type", "")
    config = body.get("config", {})

    cls = PLUGIN_REGISTRY.get(plugin_type)
    if not cls:
        return {"ok": False, "error": f"Plugin type '{plugin_type}' not available", "details": ""}

    try:
        result = await cls().test_connection(config)
    except Exception as e:
        result = {"ok": False, "error": _sanitize_plugin_error(e, "Connection test failed"), "details": ""}
    return result


#
# Note: the global "sync plugin → upsert SiUsers" endpoint was removed.
# Connectors are now used **only** during access reviews via
# POST /reviews/{rid}/import-connector. The SyncJob records still live
# (populated by the review import path) so the per-plugin history modal
# keeps working.
#


@proj_router.get("/{plugin_id}/history")
async def plugin_history(project_id: uuid.UUID, plugin_id: str, user: Optional[User] = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    result = await db.execute(
        select(SyncJob)
        .where(SyncJob.project_id == project_id, SyncJob.plugin_id == plugin_id)
        .order_by(SyncJob.started_at.desc())
        .limit(50)
    )
    return [
        {
            "id": str(j.id),
            "status": j.status,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            "users_found": j.users_found,
            "users_created": j.users_created,
            "users_updated": j.users_updated,
            "entries_created": j.entries_created,
            "error_message": j.error_message or "",
        }
        for j in result.scalars().all()
    ]




router.include_router(proj_router)
