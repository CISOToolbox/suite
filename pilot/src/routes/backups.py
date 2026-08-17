"""Backups: scheduled backup and restore of module data via internal APIs."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone, timedelta
from decimal import Decimal as _Decimal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.database import get_db, async_session
from src.models import AppSettings, Base, ModuleRegistry, User
from src.version_common import version_payload

router = APIRouter(prefix="/api/backups", tags=["backups"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

# ═══════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════

# Backups are stored in app_settings as JSON:
#   backup_config         → {module: {enabled, frequency_hours,
#                                      retention_daily, retention_weekly,
#                                      retention_monthly}}   (GFS retention)
#   backup_{module}_{ts}  → format 2 (FEAT-29):
#       {format: 2, module, timestamp, items_count,
#        meta: {module, product_version, schema_revision,
#               schema_fingerprint, created_at, created_by, items_count},
#        data: [...]}
#   Legacy top-level keys (module/timestamp/items_count) are kept so the
#   existing readers (list, scheduler freshness check, restore) work
#   unchanged; blobs without "format" are read as format 1 (unknown version).

# Modules eligible for centralized backup. A module qualifies if it
# exposes /api/internal/export, /api/internal/export/{id} and
# /api/internal/restore/{id}. All 10 modules implement the trio since
# FEAT-30 phase 1 (audit has a backend since v1; appsec and watch got
# their single-instance trio in the same change).
VALID_MODULES = ("risk", "vendor", "compliance", "audit", "asset", "access",
                 "surface", "appsec", "watch", "pilot")
import re as _re
_BACKUP_KEY_RE = _re.compile(
    r"^backup_(risk|vendor|compliance|audit|asset|access|surface|appsec|watch|pilot)_\d{8}_\d{6}$"
)

def _validate_backup_key(key: str) -> None:
    """H-4 fix: prevent reading arbitrary app_settings rows via backup endpoints."""
    if not _BACKUP_KEY_RE.match(key):
        raise HTTPException(status_code=400, detail="Invalid backup key format")


# GFS (grandfather-father-son) retention defaults: keep the most recent
# backup of each of the last N days / weeks / months. A single snapshot can
# satisfy several buckets at once (e.g. the 1st-of-month daily backup also
# counts as that month's monthly copy).
# Manual backups kept apart from GFS: the newest N per module survive.
MANUAL_RETENTION = int(os.getenv("BACKUP_MANUAL_RETENTION", "10"))

DEFAULT_RETENTION_DAILY = 7
DEFAULT_RETENTION_WEEKLY = 4
DEFAULT_RETENTION_MONTHLY = 12


class BackupConfig(BaseModel):
    module: str
    enabled: bool = True
    frequency_hours: int = 24
    retention_daily: int = DEFAULT_RETENTION_DAILY
    retention_weekly: int = DEFAULT_RETENTION_WEEKLY
    retention_monthly: int = DEFAULT_RETENTION_MONTHLY


class BackupConfigUpdate(BaseModel):
    configs: list[BackupConfig]


def _normalize_cfg(raw: dict) -> dict:
    """Return a config dict in the GFS shape, tolerating the legacy
    ``retention_count`` field (pre-GFS rows): it seeds the daily bucket,
    weekly/monthly fall back to defaults."""
    legacy = raw.get("retention_count")
    return {
        "enabled": bool(raw.get("enabled", False)),
        "frequency_hours": max(1, int(raw.get("frequency_hours", 24))),
        "retention_daily": max(0, int(raw.get("retention_daily", legacy if legacy is not None else DEFAULT_RETENTION_DAILY))),
        "retention_weekly": max(0, int(raw.get("retention_weekly", DEFAULT_RETENTION_WEEKLY))),
        "retention_monthly": max(0, int(raw.get("retention_monthly", DEFAULT_RETENTION_MONTHLY))),
    }


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

async def _get_backup_config(db: AsyncSession) -> dict:
    result = await db.execute(select(AppSettings).where(AppSettings.key == "backup_config"))
    s = result.scalar_one_or_none()
    if s and s.value:
        try:
            return json.loads(s.value)
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


async def _set_backup_config(config: dict, db: AsyncSession) -> None:
    result = await db.execute(select(AppSettings).where(AppSettings.key == "backup_config"))
    s = result.scalar_one_or_none()
    val = json.dumps(config)
    if s:
        s.value = val
    else:
        db.add(AppSettings(key="backup_config", value=val))


@router.get("/config")
async def get_config(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    config = await _get_backup_config(db)
    # Normalize every entry to the GFS shape and ensure all modules present.
    out = {}
    for mod in VALID_MODULES:
        out[mod] = _normalize_cfg(config.get(mod, {}))
    return out


@router.put("/config")
async def update_config(body: BackupConfigUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    config = {}
    for c in body.configs:
        if c.module not in VALID_MODULES:
            continue
        config[c.module] = {
            "enabled": c.enabled,
            "frequency_hours": max(1, c.frequency_hours),
            "retention_daily": max(0, c.retention_daily),
            "retention_weekly": max(0, c.retention_weekly),
            "retention_monthly": max(0, c.retention_monthly),
        }
    await _set_backup_config(config, db)
    # Disabling/retuning backups must leave a trace (FEAT-30 review).
    from src.audit import log_write
    await log_write(db, user, None, "backup.config_update",
                    entity_type="backup", entity_id="config",
                    details={m: c.get("enabled") for m, c in config.items()})
    await db.commit()
    return config


# ═══════════════════════════════════════════════════════════════
# BACKUP EXECUTION
# ═══════════════════════════════════════════════════════════════

# ── Pilot self-backup ─────────────────────────────────────────────
#
# When ``module_id == "pilot"`` we skip the HTTP loopback entirely and
# read straight from the local DB. The snapshot wraps the rest of the
# Pilot domain: users, personnel, AppSettings (minus ``backup_*`` to
# avoid recursion and minus ``ai_*`` so a restore on a different
# deployment does not leak provider credentials), the ModuleRegistry,
# the consolidated projects (with their measures) and the
# MeasureCache. The snapshot is wrapped in the same envelope as a
# per-module backup (``[{id, name, organization, data}]``) so the rest
# of the loop (run / list / restore / retention) is unchanged.

_PILOT_INSTANCE_ID = "pilot"


def _serialize_row(obj, skip=()) -> dict:
    # Timestamps (created_at/updated_at/last_login) ARE exported: a restore
    # that claims to reproduce a dated state must keep the original dates.
    # The restore-side _coerce parses the ISO strings back to datetimes.
    out: dict = {}
    for col in obj.__table__.columns:
        if col.name in skip:
            continue
        v = getattr(obj, col.name)
        if isinstance(v, datetime):
            v = v.isoformat()
        elif isinstance(v, _Decimal):
            # Numeric columns (e.g. kpi_snapshot.value) — json.dumps refuses
            # Decimal and a single one used to 500 the whole run-all.
            v = float(v)
        elif hasattr(v, "hex") and not isinstance(v, (bytes, bytearray)):
            v = str(v)
        out[col.name] = v
    return out


async def _pilot_self_export(db: AsyncSession) -> list[dict]:
    """Read every Pilot-owned table and wrap as a single export item."""
    # Imported here to avoid a circular import at module load.
    from src.models import (
        AppSettings as _AppSettings,
        EvidenceCache as _EvidenceCache,
        KpiDefinition as _KpiDefinition,
        KpiFrameworkMapping as _KpiFrameworkMapping,
        KpiSnapshot as _KpiSnapshot,
        KpiTombstone as _KpiTombstone,
        MeasureCache as _MeasureCache,
        ModuleRegistry as _ModuleRegistry,
        Personnel as _Personnel,
        Project as _Project,
        ProjectMeasure as _ProjectMeasure,
        User as _User,
    )

    users = (await db.execute(select(_User))).scalars().all()
    personnel = (await db.execute(select(_Personnel))).scalars().all()
    registry = (await db.execute(select(_ModuleRegistry))).scalars().all()
    projects = (await db.execute(select(_Project))).scalars().all()
    project_measures = (await db.execute(select(_ProjectMeasure))).scalars().all()
    measure_cache = (await db.execute(select(_MeasureCache))).scalars().all()
    evidence_cache = (await db.execute(select(_EvidenceCache))).scalars().all()
    kpi_definitions = (await db.execute(select(_KpiDefinition))).scalars().all()
    kpi_mappings = (await db.execute(select(_KpiFrameworkMapping))).scalars().all()
    kpi_snapshots = (await db.execute(select(_KpiSnapshot))).scalars().all()
    kpi_tombstones = (await db.execute(select(_KpiTombstone))).scalars().all()
    # AppSettings: exclude the backup_* keys (recursion) and the
    # ai_* keys (deployment-specific runtime).
    settings_rows = (await db.execute(select(_AppSettings))).scalars().all()
    safe_settings = [
        {"key": s.key, "value": s.value}
        for s in settings_rows
        if not s.key.startswith("backup_") and not s.key.startswith("ai_")
    ]

    return [{
        "id": _PILOT_INSTANCE_ID,
        "name": "Pilot instance",
        "organization": "",
        "data": {
            "users": [_serialize_row(u) for u in users],
            "personnel": [_serialize_row(p) for p in personnel],
            "module_registry": [_serialize_row(m) for m in registry],
            "projects": [_serialize_row(p) for p in projects],
            "project_measures": [_serialize_row(m) for m in project_measures],
            "measure_cache": [_serialize_row(m) for m in measure_cache],
            "evidence_cache": [_serialize_row(e) for e in evidence_cache],
            "kpi_definitions": [_serialize_row(k) for k in kpi_definitions],
            "kpi_framework_mappings": [_serialize_row(k) for k in kpi_mappings],
            "kpi_snapshots": [_serialize_row(k) for k in kpi_snapshots],
            "kpi_tombstones": [_serialize_row(k) for k in kpi_tombstones],
            "app_settings": safe_settings,
        },
    }]


async def _pilot_self_restore(db: AsyncSession, data: dict) -> dict:
    """Overwrite Pilot's own state from a self-backup payload.

    Order: clear children before parents, then re-insert parents
    before children. ``backup_*`` and ``ai_*`` AppSettings rows are
    left untouched.
    """
    from sqlalchemy import delete as _delete
    from src.models import (
        AppSettings as _AppSettings,
        EvidenceCache as _EvidenceCache,
        KpiDefinition as _KpiDefinition,
        KpiFrameworkMapping as _KpiFrameworkMapping,
        KpiSnapshot as _KpiSnapshot,
        KpiTombstone as _KpiTombstone,
        MeasureCache as _MeasureCache,
        ModuleRegistry as _ModuleRegistry,
        Personnel as _Personnel,
        Project as _Project,
        ProjectMeasure as _ProjectMeasure,
        User as _User,
    )

    def _coerce(model, payload):
        # Type-aware: _serialize_row emits datetimes/dates as ISO strings;
        # asyncpg needs real datetime/date objects back.
        from sqlalchemy import Date as _Date, DateTime as _DateTime
        from datetime import date as _date
        cols = {c.name: c for c in model.__table__.columns}
        out = {}
        for k, v in payload.items():
            if k not in cols:
                continue
            if isinstance(v, str):
                try:
                    if isinstance(cols[k].type, _DateTime):
                        v = datetime.fromisoformat(v)
                    elif isinstance(cols[k].type, _Date):
                        v = _date.fromisoformat(v)
                except ValueError:
                    v = None
            out[k] = v
        return out

    # Children first
    await db.execute(_delete(_ProjectMeasure))
    await db.execute(_delete(_MeasureCache))
    await db.execute(_delete(_EvidenceCache))
    await db.execute(_delete(_KpiSnapshot))
    await db.execute(_delete(_KpiFrameworkMapping))
    await db.execute(_delete(_KpiDefinition))
    await db.execute(_delete(_KpiTombstone))
    await db.execute(_delete(_Project))
    await db.execute(_delete(_Personnel))
    await db.execute(_delete(_ModuleRegistry))
    await db.execute(_delete(_User))
    # AppSettings: only wipe the keys we are about to rewrite — leave
    # backup_* and ai_* untouched (so the restore does not delete the
    # other backups it is filed alongside).
    for s in data.get("app_settings") or []:
        k = s.get("key")
        if k and not k.startswith("backup_") and not k.startswith("ai_"):
            await db.execute(_delete(_AppSettings).where(_AppSettings.key == k))

    # Parents first, then children
    for row in data.get("users") or []:
        db.add(_User(**_coerce(_User, row)))
    for row in data.get("personnel") or []:
        db.add(_Personnel(**_coerce(_Personnel, row)))
    for row in data.get("module_registry") or []:
        db.add(_ModuleRegistry(**_coerce(_ModuleRegistry, row)))
    for row in data.get("projects") or []:
        db.add(_Project(**_coerce(_Project, row)))
    for row in data.get("kpi_definitions") or []:
        db.add(_KpiDefinition(**_coerce(_KpiDefinition, row)))
    await db.flush()
    for row in data.get("project_measures") or []:
        db.add(_ProjectMeasure(**_coerce(_ProjectMeasure, row)))
    for row in data.get("measure_cache") or []:
        db.add(_MeasureCache(**_coerce(_MeasureCache, row)))
    for row in data.get("evidence_cache") or []:
        db.add(_EvidenceCache(**_coerce(_EvidenceCache, row)))
    for row in data.get("kpi_framework_mappings") or []:
        db.add(_KpiFrameworkMapping(**_coerce(_KpiFrameworkMapping, row)))
    for row in data.get("kpi_snapshots") or []:
        db.add(_KpiSnapshot(**_coerce(_KpiSnapshot, row)))
    for row in data.get("kpi_tombstones") or []:
        db.add(_KpiTombstone(**_coerce(_KpiTombstone, row)))
    for s in data.get("app_settings") or []:
        k = s.get("key")
        if k and not k.startswith("backup_") and not k.startswith("ai_"):
            db.add(_AppSettings(key=k, value=s.get("value", "")))

    await db.commit()
    return {"ok": True, "id": _PILOT_INSTANCE_ID}


async def _fetch_module_data(module_id: str, internal_url: str) -> list[dict] | None:
    """Fetch all data from a module via internal export endpoints.
    For ``module_id == "pilot"`` we read directly from the local DB
    so Pilot can back itself up without an HTTP loopback (and without
    needing to know its own URL)."""
    if module_id == "pilot":
        try:
            async with async_session() as db:
                return await _pilot_self_export(db)
        except Exception as e:
            import logging
            logging.getLogger("pilot").warning(f"Pilot self-backup failed: {e}")
            return None

    headers = {"X-Service-Token": SERVICE_TOKEN}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            list_url = internal_url.rstrip("/") + "/api/internal/export"
            resp = await client.get(list_url, headers=headers)
            if not resp.is_success:
                return None
            items = resp.json()

            full_items = []
            for item in items:
                item_id = item.get("id", "")
                if not item_id:
                    continue
                detail_url = internal_url.rstrip("/") + f"/api/internal/export/{item_id}"
                dr = await client.get(detail_url, headers=headers)
                if dr.is_success:
                    full_items.append(dr.json())
            return full_items
    except Exception as e:
        import logging
        logging.getLogger("pilot").warning(f"Backup fetch failed for {module_id}: {e}")
        return None


async def _module_version_meta(module_id: str, internal_url: str, db: AsyncSession) -> dict:
    """Version identity of the backup source (FEAT-29 meta). Best-effort:
    a module that predates /api/version yields an empty dict → null fields."""
    if module_id == "pilot":
        try:
            return await version_payload("pilot", Base.metadata, db)
        except Exception:
            return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(internal_url.rstrip("/") + "/api/version")
            if resp.is_success:
                return resp.json()
    except Exception:
        pass
    return {}


def _build_backup_value(module_id: str, data: list, version_meta: dict, created_by: str | None) -> str:
    """Serialize a format-2 backup blob (FEAT-29). See the storage comment
    at the top of this module for the layout and compat rules."""
    now = datetime.now(timezone.utc).isoformat()
    return json.dumps({
        "format": 2,
        "module": module_id,
        "timestamp": now,
        "items_count": len(data),
        "meta": {
            "module": module_id,
            "product_version": version_meta.get("product_version"),
            "schema_revision": version_meta.get("schema_revision"),
            "schema_fingerprint": version_meta.get("schema_fingerprint"),
            "created_at": now,
            "created_by": created_by,
            "items_count": len(data),
        },
        "data": data,
    }, default=str)


@router.post("/run/{module_id}")
async def run_backup(module_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Manually trigger a backup for a specific module."""
    require_admin(user)
    if module_id not in VALID_MODULES:
        raise HTTPException(status_code=400, detail=f"Invalid module: {module_id}")

    # Pilot self-backup bypasses the ModuleRegistry / HTTP loopback.
    if module_id == "pilot":
        internal_url = ""
        data = await _fetch_module_data("pilot", "")
    else:
        result = await db.execute(select(ModuleRegistry).where(ModuleRegistry.id == module_id))
        mod = result.scalar_one_or_none()
        if not mod or not mod.internal_url:
            raise HTTPException(status_code=404, detail=f"Module {module_id} not found or no backend")
        internal_url = mod.internal_url
        data = await _fetch_module_data(module_id, internal_url)

    if data is None:
        raise HTTPException(status_code=502, detail=f"Failed to fetch data from {module_id}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    key = f"backup_{module_id}_{ts}"
    vmeta = await _module_version_meta(module_id, internal_url, db)
    backup_value = _build_backup_value(module_id, data, vmeta, user.email if user else None)

    db.add(AppSettings(key=key, value=backup_value))
    from src.audit import log_write
    await log_write(db, user, None, "backup.run",
                    entity_type="backup", entity_id=key, target=module_id)
    await db.commit()

    # Apply retention
    await _apply_retention(module_id, db)

    return {"ok": True, "key": key, "items": len(data), "timestamp": ts}


@router.post("/run-all")
async def run_all_backups(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Trigger backup for all enabled modules."""
    require_admin(user)
    config = await _get_backup_config(db)
    report = {}

    result = await db.execute(select(ModuleRegistry))
    mods = {m.id: m for m in result.scalars().all()}

    for mod_id, cfg in config.items():
        if not cfg.get("enabled"):
            report[mod_id] = "disabled"
            continue
        if mod_id == "pilot":
            internal_url = ""
            data = await _fetch_module_data("pilot", "")
        else:
            mod = mods.get(mod_id)
            if not mod or not mod.internal_url:
                report[mod_id] = "no backend"
                continue
            internal_url = mod.internal_url
            data = await _fetch_module_data(mod_id, internal_url)
        if data is None:
            report[mod_id] = "fetch failed"
            continue

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key = f"backup_{mod_id}_{ts}"
        vmeta = await _module_version_meta(mod_id, internal_url, db)
        backup_value = _build_backup_value(mod_id, data, vmeta, user.email if user else None)
        db.add(AppSettings(key=key, value=backup_value))
        report[mod_id] = f"ok ({len(data)} items)"

    from src.audit import log_write
    await log_write(db, user, None, "backup.run_all",
                    entity_type="backup", entity_id="", details=report)
    await db.commit()

    # Apply retention for all modules
    for mod_id, cfg in config.items():
        if cfg.get("enabled"):
            await _apply_retention(mod_id, db)

    return report


# ═══════════════════════════════════════════════════════════════
# BACKUP LIST + DOWNLOAD + RESTORE
# ═══════════════════════════════════════════════════════════════

@router.get("/list")
async def list_backups(module: str | None = None, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    if module and module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    prefix = f"backup_{module}_" if module else "backup_"
    result = await db.execute(
        select(AppSettings).where(AppSettings.key.like(prefix + "%")).order_by(AppSettings.key.desc())
    )
    backups = []
    for s in result.scalars().all():
        try:
            meta = json.loads(s.value)
            vmeta = meta.get("meta", {}) if meta.get("format", 1) >= 2 else {}
            created_by = vmeta.get("created_by")
            backups.append({
                "key": s.key,
                "module": meta.get("module", ""),
                "timestamp": meta.get("timestamp", ""),
                "items_count": meta.get("items_count", 0),
                "size_kb": round(len(s.value) / 1024, 1),
                "format": meta.get("format", 1),
                "product_version": vmeta.get("product_version"),
                "schema_revision": vmeta.get("schema_revision"),
                "created_by": created_by,
                "manual": bool(created_by) and created_by != "scheduler",
            })
        except (json.JSONDecodeError, TypeError):
            pass
    return backups


@router.get("/download/{backup_key}")
async def download_backup(backup_key: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    _validate_backup_key(backup_key)
    result = await db.execute(select(AppSettings).where(AppSettings.key == backup_key))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Backup not found")
    return Response(
        content=s.value,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{backup_key}.json"'},
    )


@router.post("/restore/{backup_key}")
async def restore_backup(backup_key: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Restore a backup to its source module."""
    require_admin(user)
    _validate_backup_key(backup_key)
    result = await db.execute(select(AppSettings).where(AppSettings.key == backup_key))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Backup not found")

    try:
        backup = json.loads(s.value)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid backup data")

    module_id = backup.get("module", "")
    items = backup.get("data", [])

    # FEAT-30 P1.6: a restore rewrites a whole module — always journaled,
    # with the triggering admin, the backup key and the target module.
    from src.audit import log_write
    await log_write(db, user, None, "backup.restore",
                    entity_type="backup", entity_id=backup_key, target=module_id, commit=True)

    # Pilot self-restore: in-process, no HTTP indirection.
    if module_id == "pilot":
        restored = 0
        errors = 0
        for item in items:
            item_data = item.get("data", {})
            try:
                await _pilot_self_restore(db, item_data)
                restored += 1
            except Exception as e:
                import logging
                logging.getLogger("pilot").warning(f"Pilot self-restore failed: {e}")
                errors += 1
        # Lockout guard: the restore wipes+rewrites `users`; if the backup
        # predates the admin who triggered it, they would lose access the
        # moment the transaction lands. Re-insert them (admin) if absent.
        if user is not None:
            existing = await db.execute(select(User).where(User.email == user.email))
            if existing.scalar_one_or_none() is None:
                db.add(User(email=user.email, name=user.name, picture=user.picture,
                            provider=user.provider, provider_id=user.provider_id,
                            role="admin", modules=user.modules or []))
                await db.commit()
        return {"ok": True, "module": "pilot", "restored": restored, "errors": errors}

    result = await db.execute(select(ModuleRegistry).where(ModuleRegistry.id == module_id))
    mod = result.scalar_one_or_none()
    if not mod or not mod.internal_url:
        raise HTTPException(status_code=404, detail=f"Module {module_id} not found")

    # Restore via internal API endpoints
    headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}
    restored = 0
    errors = 0

    async with httpx.AsyncClient(timeout=60.0) as client:
        for item in items:
            item_id = item.get("id", "")
            data = item.get("data", {})
            if not item_id:
                continue

            url = mod.internal_url.rstrip("/") + f"/api/internal/restore/{item_id}"
            resp = await client.put(url, headers=headers, json={
                "name": item.get("name", ""),
                "organization": item.get("organization", ""),
                "data": data,
            })

            if resp.is_success:
                restored += 1
            else:
                import logging
                logging.getLogger("pilot").warning(f"Restore failed for {module_id}/{item_id}: {resp.status_code} {resp.text[:200]}")
                errors += 1

    return {"ok": True, "module": module_id, "restored": restored, "errors": errors}


@router.delete("/{backup_key}")
async def delete_backup(backup_key: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    _validate_backup_key(backup_key)
    result = await db.execute(select(AppSettings).where(AppSettings.key == backup_key))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Backup not found")
    from src.audit import log_write
    await log_write(db, user, None, "backup.delete",
                    entity_type="backup", entity_id=backup_key)
    await db.delete(s)
    await db.commit()
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════
# RETENTION
# ═══════════════════════════════════════════════════════════════

def _key_timestamp(key: str) -> datetime | None:
    """Parse the ``YYYYMMDD_HHMMSS`` suffix of a ``backup_<mod>_...`` key."""
    m = _re.search(r"_(\d{8})_(\d{6})$", key)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
    except ValueError:
        return None


def _gfs_keep(keys: list[str], daily: int, weekly: int, monthly: int) -> set[str]:
    """Given backup keys (each carrying a ``_YYYYMMDD_HHMMSS`` suffix), return
    the set to KEEP under a grandfather-father-son policy: the most recent
    backup of each of the last ``daily`` days, ``weekly`` ISO weeks and
    ``monthly`` months. Keys with an unparseable timestamp are always kept
    (never delete something we can't date)."""
    dated = [(k, _key_timestamp(k)) for k in keys]
    keep = {k for k, ts in dated if ts is None}
    ordered = sorted(((k, ts) for k, ts in dated if ts is not None),
                     key=lambda x: x[1], reverse=True)

    def _bucket(fmt: str, count: int) -> None:
        if count <= 0:
            return
        seen: dict[str, str] = {}
        for k, ts in ordered:
            b = ts.strftime(fmt)
            if b not in seen:          # newest key wins (ordered desc)
                seen[b] = k
        for b in list(seen.keys())[:count]:
            keep.add(seen[b])

    _bucket("%Y-%m-%d", daily)    # daily
    _bucket("%G-%V", weekly)      # ISO year-week
    _bucket("%Y-%m", monthly)     # monthly
    return keep


async def _apply_retention(module_id: str, db: AsyncSession) -> None:
    config = await _get_backup_config(db)
    cfg = _normalize_cfg(config.get(module_id, {}))

    prefix = f"backup_{module_id}_"
    result = await db.execute(
        select(AppSettings).where(AppSettings.key.like(prefix + "%"))
    )
    backups = result.scalars().all()

    # Manual backups (run by an admin — incl. the automatic pre-restore
    # safety backups) live OUTSIDE the GFS buckets: several manual runs the
    # same day must not overwrite each other. They have their own cap.
    def _is_manual(b) -> bool:
        try:
            blob = json.loads(b.value)
            created_by = (blob.get("meta") or {}).get("created_by")
            return bool(created_by) and created_by != "scheduler"
        except (json.JSONDecodeError, TypeError, AttributeError):
            return False   # legacy format-1: keep GFS semantics

    manual = [b for b in backups if _is_manual(b)]
    scheduled = [b for b in backups if b not in manual]

    keep = _gfs_keep(
        [b.key for b in scheduled],
        cfg["retention_daily"], cfg["retention_weekly"], cfg["retention_monthly"],
    )
    # Manual cap: newest MANUAL_RETENTION per module (key sorts by timestamp).
    manual_keep = {b.key for b in sorted(manual, key=lambda b: b.key, reverse=True)[:MANUAL_RETENTION]}
    deleted_keys = []
    for b in scheduled:
        if b.key not in keep:
            await db.delete(b)
            deleted_keys.append(b.key)
    for b in manual:
        if b.key not in manual_keep:
            await db.delete(b)
            deleted_keys.append(b.key)
    if deleted_keys:
        # Retention destroys restore points — journaled (FEAT-30 review).
        from src.audit import log_write
        await log_write(db, None, None, "backup.retention_expire", actor="scheduler",
                        entity_type="backup", entity_id=module_id,
                        details={"deleted": deleted_keys})
        await db.commit()


# ═══════════════════════════════════════════════════════════════
# SCHEDULED BACKUP (background task)
# ═══════════════════════════════════════════════════════════════

_backup_task = None


async def _backup_loop():
    """Background loop: check every 10 minutes if any module needs backup."""
    while True:
        await asyncio.sleep(600)  # 10 minutes
        try:
            async with async_session() as db:
                config = await _get_backup_config(db)
                result = await db.execute(select(ModuleRegistry))
                mods = {m.id: m for m in result.scalars().all()}

                for mod_id, cfg in config.items():
                    if not cfg.get("enabled"):
                        continue
                    freq_hours = cfg.get("frequency_hours", 24)
                    # Pilot self-backup needs no ModuleRegistry entry.
                    if mod_id != "pilot":
                        mod = mods.get(mod_id)
                        if not mod or not mod.internal_url:
                            continue
                        internal_url = mod.internal_url
                    else:
                        internal_url = ""

                    # Check last backup timestamp
                    prefix = f"backup_{mod_id}_"
                    result2 = await db.execute(
                        select(AppSettings).where(AppSettings.key.like(prefix + "%")).order_by(AppSettings.key.desc()).limit(1)
                    )
                    last = result2.scalar_one_or_none()
                    should_backup = True
                    if last:
                        try:
                            meta = json.loads(last.value)
                            last_ts = datetime.fromisoformat(meta["timestamp"])
                            if datetime.now(timezone.utc) - last_ts < timedelta(hours=freq_hours):
                                should_backup = False
                        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                            pass

                    if should_backup:
                        data = await _fetch_module_data(mod_id, internal_url)
                        if data is not None:
                            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                            key = f"backup_{mod_id}_{ts}"
                            vmeta = await _module_version_meta(mod_id, internal_url, db)
                            db.add(AppSettings(key=key, value=_build_backup_value(
                                mod_id, data, vmeta, "scheduler")))
                            from src.audit import log_write
                            await log_write(db, None, None, "backup.run", actor="scheduler",
                                            entity_type="backup", entity_id=key, target=mod_id)
                            await db.commit()
                            await _apply_retention(mod_id, db)
        except Exception:
            pass  # Don't crash the background task


def start_backup_scheduler():
    global _backup_task
    if _backup_task is None:
        _backup_task = asyncio.create_task(_backup_loop())
