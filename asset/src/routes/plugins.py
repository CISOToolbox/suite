"""Asset plugin connectors — CRUD + test + sync + history.

Sanitisation note: ip_address and criticite are validated at the
merge layer (see _merge_field) so connector-provided garbage can't
land in the DB. Any other connector field is cast via str() before
storage — SQLAlchemy parameterises, so SQL injection is not a risk
but display-layer XSS is caught by esc() in the frontend.

Mirrors the pattern from access/src/routes/plugins.py. The sync path
upserts Asset rows matched by `external_key` stored in
Asset.notes (key=value pattern). When an asset already exists with
the same external_key, only the following fields are refreshed on
re-sync — preserving any manual edits made since the previous sync:
  os, version, last_login_at, statut (only if connector says inactive
  and the row wasn't manually overridden).
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time as _time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.crypto import decrypt_config, encrypt_config
from src.database import get_db
from src.models import Asset, AssetPluginConfig, AssetSyncJob, User
from src.plugins import PLUGIN_REGISTRY
from src.routes.auth_helpers import get_project_or_404

router = APIRouter(prefix="/api", tags=["asset-plugins"])

# ─── Rate limiter (per-user sliding window) ──────────────────────
# In-memory bucket, safe under asyncio single-threaded execution.
# Bounded size: if we ever exceed _BUCKETS_MAX keys (rogue scan?), we
# drop the oldest entries. Stale buckets are pruned opportunistically
# on every call so long-lived processes don't leak memory.
_RATE_WINDOW = 60
_RATE_MAX = 10
_BUCKETS_MAX = 10_000
_BUCKETS: dict[str, list[float]] = {}


def _rate_limit(user: Optional[User], key: str) -> None:
    if user is None:
        return
    bk = f"{user.email or user.id}:{key}"
    now = _time.monotonic()
    cutoff = now - _RATE_WINDOW

    # Opportunistic prune: if we're near the cap, drop buckets whose
    # newest timestamp is outside the window.
    if len(_BUCKETS) > _BUCKETS_MAX // 2:
        for k in list(_BUCKETS.keys()):
            ts = _BUCKETS[k]
            if not ts or ts[-1] < cutoff:
                del _BUCKETS[k]
    # Hard cap: drop oldest to make room.
    if len(_BUCKETS) >= _BUCKETS_MAX and bk not in _BUCKETS:
        try:
            _BUCKETS.pop(next(iter(_BUCKETS)))
        except StopIteration:
            pass

    win = _BUCKETS.setdefault(bk, [])
    win[:] = [t for t in win if t > cutoff]
    if len(win) >= _RATE_MAX:
        raise HTTPException(status_code=429,
                            detail=f"Rate limit: max {_RATE_MAX}/{_RATE_WINDOW}s on {key}")
    win.append(now)


def _sanitize_err(exc: Exception, context: str) -> str:
    logging.getLogger("asset-backend").exception("%s: %s", context, exc)
    return f"{context} — check server logs"


def _mask_config(cfg: dict) -> dict:
    masked: dict = {}
    for k, v in (cfg or {}).items():
        if any(s in k.lower() for s in ("secret", "password", "key", "token", "credential")):
            masked[k] = "****" if v else ""
        else:
            masked[k] = v
    return masked


def _to_dict(pc: AssetPluginConfig) -> dict:
    cfg = {}
    if pc.config_enc:
        try:
            cfg = _mask_config(decrypt_config(pc.config_enc))
        except Exception:
            cfg = {}
    return {
        "id": pc.id,
        "plugin_type": pc.plugin_type,
        "label": pc.label or "",
        "enabled": pc.enabled,
        "priority": pc.priority,
        "config": cfg,
        "filters": pc.filters or {},
        "schedule": pc.schedule,
        "last_sync_at": pc.last_sync_at.isoformat() if pc.last_sync_at else None,
        "last_sync_status": pc.last_sync_status or "",
    }


# ─── Global endpoints ────────────────────────────────────────────

@router.get("/plugins/available")
async def list_available_plugins():
    """Plugin types registered in this deployment + their config schema."""
    return [
        {
            "type": cls.plugin_type,
            "label": cls.label,
            "label_en": cls.label_en,
            "config_schema": cls.config_schema,
            "setup_guide": cls.setup_guide,
            "setup_guide_en": cls.setup_guide_en,
        }
        for cls in PLUGIN_REGISTRY.values()
    ]


# ─── Project-scoped CRUD ─────────────────────────────────────────

proj_router = APIRouter(prefix="/api/projects/{project_id}/plugins", tags=["asset-plugins"])


@proj_router.get("")
async def list_plugins(project_id: uuid.UUID,
                       user: Optional[User] = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db)
    result = await db.execute(
        select(AssetPluginConfig)
        .where(AssetPluginConfig.project_id == project_id)
        .order_by(AssetPluginConfig.sort_order)
    )
    return [_to_dict(pc) for pc in result.scalars().all()]


@proj_router.post("", status_code=201)
async def create_plugin(project_id: uuid.UUID, body: dict,
                        user: Optional[User] = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    require_admin(user)
    project = await get_project_or_404(project_id, user, db)
    ptype = body.get("plugin_type", "")
    if ptype not in PLUGIN_REGISTRY:
        raise HTTPException(status_code=400, detail=f"Unknown plugin type: {ptype}")

    # Next id / sort_order
    result = await db.execute(
        select(AssetPluginConfig).where(AssetPluginConfig.project_id == project_id)
    )
    existing = result.scalars().all()
    max_num = 0
    for pc in existing:
        try:
            n = int(re.sub(r"\D", "", pc.id) or "0")
            if n > max_num:
                max_num = n
        except ValueError:
            pass
    max_order = await db.scalar(
        select(func.coalesce(func.max(AssetPluginConfig.sort_order), 0))
        .where(AssetPluginConfig.project_id == project_id)
    )

    config_data = body.get("config") or {}
    config_enc = encrypt_config(config_data) if config_data else ""

    pc = AssetPluginConfig(
        project_id=project_id,
        id=f"APL-{max_num + 1:03d}",
        sort_order=(max_order or 0) + 1,
        plugin_type=ptype,
        label=body.get("label", ""),
        enabled=body.get("enabled", False),
        priority=int(body.get("priority", 100) or 100),
        config_enc=config_enc,
        filters=body.get("filters") or {},
        schedule=body.get("schedule", "manual"),
    )
    db.add(pc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(pc)
    return _to_dict(pc)


@proj_router.patch("/{plugin_id}")
async def patch_plugin(project_id: uuid.UUID, plugin_id: str, body: dict,
                       user: Optional[User] = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    require_admin(user)
    project = await get_project_or_404(project_id, user, db)
    pc = await db.get(AssetPluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")

    for f in ("label", "schedule"):
        if f in body:
            setattr(pc, f, str(body[f]) if body[f] is not None else "")
    if "enabled" in body:
        pc.enabled = bool(body["enabled"])
    if "priority" in body:
        try:
            pc.priority = int(body["priority"] or 100)
        except (TypeError, ValueError):
            pc.priority = 100
    if "filters" in body and isinstance(body["filters"], dict):
        pc.filters = body["filters"]
    if "config" in body and isinstance(body["config"], dict):
        new_config = body["config"]
        # Merge: keep existing value for masked (****) fields
        if pc.config_enc:
            try:
                old = decrypt_config(pc.config_enc)
                for k, v in new_config.items():
                    if v == "****" and k in old:
                        new_config[k] = old[k]
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
async def delete_plugin(project_id: uuid.UUID, plugin_id: str,
                        user: Optional[User] = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    require_admin(user)
    project = await get_project_or_404(project_id, user, db)
    pc = await db.get(AssetPluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")
    await db.delete(pc)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()


@proj_router.post("/{plugin_id}/test")
async def test_plugin(project_id: uuid.UUID, plugin_id: str,
                      user: Optional[User] = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    require_admin(user)
    _rate_limit(user, "asset-plugin-test")
    await get_project_or_404(project_id, user, db)
    pc = await db.get(AssetPluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")
    cls = PLUGIN_REGISTRY.get(pc.plugin_type)
    if not cls:
        return {"ok": False, "error": f"Plugin type '{pc.plugin_type}' not available"}
    config = {}
    if pc.config_enc:
        try:
            config = decrypt_config(pc.config_enc)
        except Exception as e:
            return {"ok": False, "error": _sanitize_err(e, "Cannot decrypt config"), "details": ""}
    try:
        result = await cls().test_connection(config)
    except Exception as e:
        result = {"ok": False, "error": _sanitize_err(e, "Connection test failed"), "details": ""}
    return result


@router.post("/projects/{project_id}/plugins/test-config")
async def test_plugin_config(project_id: uuid.UUID, request: Request,
                             user: Optional[User] = Depends(get_current_user),
                             db: AsyncSession = Depends(get_db)):
    """Admin-only + rate-limited — test an unsaved config."""
    require_admin(user)
    _rate_limit(user, "asset-plugin-test-config")
    await get_project_or_404(project_id, user, db, require_perm="edit")
    body = await request.json()
    ptype = body.get("plugin_type", "")
    config = body.get("config", {})
    cls = PLUGIN_REGISTRY.get(ptype)
    if not cls:
        return {"ok": False, "error": f"Plugin type '{ptype}' not available"}
    try:
        result = await cls().test_connection(config)
    except Exception as e:
        result = {"ok": False, "error": _sanitize_err(e, "Connection test failed"), "details": ""}
    return result


# ─── Sync (the actual upsert into Asset table) ───────────────────

_EXT_KEY_RE = re.compile(r"(?:^|\|\s*)external_key=([^\s|]+)")

# Fields that connectors can provide — each is merged under the
# priority rule: higher pc.priority wins when two plugins target the
# same field. Listed here so the merge loop is data-driven.
_CONNECTOR_FIELDS = (
    "type", "description", "criticite", "proprietaire", "localisation",
    "os", "version", "fournisseur", "fin_support", "fin_vie",
    "statut", "ip_address", "last_login_at",
)


def _read_external_key(notes: str) -> str:
    """Legacy: first plugin iteration stored the external_key in notes
    (`external_key=xxx | ...`). Still honoured on first sync after the
    004 migration so existing rows are caught by the new sources map."""
    if not notes:
        return ""
    m = _EXT_KEY_RE.search(notes)
    return m.group(1).strip().lower() if m else ""


def _norm_hostname(name: str) -> str:
    """Lowercased + domain-stripped hostname, used as the fallback key
    to dedupe the same machine reported by multiple connectors."""
    if not name:
        return ""
    return name.strip().split(".", 1)[0].lower()


def _merge_field(asset: Asset, field: str, new_value, plugin_id: str,
                 plugin_priority: int, priority_map: dict[str, int],
                 sources: dict) -> bool:
    """Apply ``new_value`` to ``asset.field`` unless another plugin with
    strictly higher priority has already claimed it. Returns True if
    the stored value actually changed.

    Sentinel ``sources.fields[field] == "manual"`` marks a human edit
    and always wins — connectors never overwrite manual edits,
    regardless of their priority. This lets CISOs override a connector
    value (e.g. fix a wrong hostname) without fighting the next sync."""
    if new_value is None or new_value == "":
        return False
    fields_map = sources.setdefault("fields", {})
    owner_id = fields_map.get(field)
    # Manual edit wins over any connector, always.
    if owner_id == "manual":
        return False
    if owner_id and owner_id != plugin_id:
        owner_priority = priority_map.get(owner_id, 0)
        if owner_priority > plugin_priority:
            return False
    if field == "criticite":
        new_value = max(1, min(5, int(new_value or 2)))
    elif field == "ip_address":
        # Drop anything that's not a valid IPv4/IPv6 literal.
        try:
            new_value = str(ipaddress.ip_address(str(new_value).strip()))
        except (ValueError, TypeError):
            return False
    elif field in ("nom", "description", "os", "version", "fournisseur",
                   "localisation", "proprietaire", "notes"):
        # String columns: cap at model-declared length to avoid overflow.
        new_value = str(new_value or "")[:500]
    old = getattr(asset, field, None)
    changed = old != new_value
    setattr(asset, field, new_value)
    fields_map[field] = plugin_id
    return changed


def _reconcile_retired(existing, present_ids, plugin_id, now):
    """Retire assets this plugin owns but no longer returns.

    `sources["seen"] = {plugin_id: ts}` tracks which connectors still see
    each asset. For every asset owned by ``plugin_id`` (present in
    ``sources["keys"]``) that is NOT in ``present_ids`` (i.e. the plugin
    did not return it this run), drop the plugin from ``seen``; once no
    connector still sees the asset, set ``statut="retire"``. An asset seen
    by another connector stays active (multi-source rule).

    Legacy rows without a ``seen`` map are seeded from ``keys`` first, so a
    single absent connector can't retire a multi-source asset on the first
    sync after this feature shipped.

    Mutates ``existing`` assets in place; returns the number retired.
    """
    now_iso = now.isoformat()
    retired = 0
    for a in existing:
        srcs = dict(a.sources or {})
        keys_map = srcs.get("keys") or {}
        if plugin_id not in keys_map or a.id in present_ids:
            continue
        seen = srcs.get("seen")
        if seen is None:
            seen = {k: now_iso for k in keys_map}
        seen = dict(seen)
        seen.pop(plugin_id, None)
        srcs["seen"] = seen
        if not seen and a.statut != "retire":
            a.statut = "retire"
            srcs.setdefault("fields", {})["statut"] = plugin_id
            a.updated_at = now
            retired += 1
        a.sources = srcs
    return retired


@proj_router.post("/{plugin_id}/sync")
async def sync_plugin(project_id: uuid.UUID, plugin_id: str,
                      user: Optional[User] = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    require_admin(user)
    _rate_limit(user, "asset-plugin-sync")
    project = await get_project_or_404(project_id, user, db, require_perm="edit")
    pc = await db.get(AssetPluginConfig, (project_id, plugin_id))
    if not pc:
        raise HTTPException(status_code=404, detail="Plugin not found")
    cls = PLUGIN_REGISTRY.get(pc.plugin_type)
    if not cls:
        raise HTTPException(status_code=400, detail=f"Plugin type '{pc.plugin_type}' not available")

    config = {}
    if pc.config_enc:
        try:
            config = decrypt_config(pc.config_enc)
        except Exception as e:
            raise HTTPException(status_code=500, detail=_sanitize_err(e, "Cannot decrypt config"))

    job = AssetSyncJob(project_id=project_id, plugin_id=plugin_id, status="running")
    db.add(job)
    await db.flush()

    try:
        sync_result = await cls().sync(config, pc.filters or {})
    except Exception as e:
        job.status = "error"
        job.error_message = _sanitize_err(e, "Sync failed")[:2000]
        job.completed_at = datetime.now(timezone.utc)
        pc.last_sync_at = datetime.now(timezone.utc)
        pc.last_sync_status = "error"
        await db.commit()
        raise HTTPException(status_code=502, detail="Connector sync failed — check server logs")

    # ── Upsert with cross-connector deduplication ──
    # The whole upsert is wrapped in try/except: any unexpected failure
    # (DB error, schema drift, coding bug) flips the job row to "error"
    # and rolls back DB state rather than leaving it in "running" forever.
    try:
        # Build priority table for all plugins of this project (used to
        # resolve field ownership when two connectors claim the same host).
        plugins_result = await db.execute(
            select(AssetPluginConfig).where(AssetPluginConfig.project_id == project_id))
        priority_map: dict[str, int] = {
            p.id: int(p.priority or 100) for p in plugins_result.scalars().all()
        }
        pc_priority = priority_map.get(pc.id, int(pc.priority or 100))

        existing_result = await db.execute(select(Asset).where(Asset.project_id == project_id))
        existing = existing_result.scalars().all()

        # Two index maps:
        #   by_key[ek]  — fast match for the SAME plugin on a re-sync
        #   by_host[h]  — cross-connector fallback match (normalised hostname)
        by_key: dict[str, Asset] = {}
        by_host: dict[str, Asset] = {}
        for a in existing:
            srcs = a.sources or {}
            keys_map = srcs.get("keys") or {}
            for kek in keys_map.values():
                if kek:
                    by_key[str(kek).lower()] = a
            # Legacy rows: external_key still buried in notes
            legacy = _read_external_key(a.notes or "")
            if legacy:
                by_key.setdefault(legacy, a)
            h = _norm_hostname(a.nom)
            if h:
                by_host.setdefault(h, a)

        max_num = 0
        for a in existing:
            try:
                n = int(re.sub(r"\D", "", a.id) or "0")
                if n > max_num:
                    max_num = n
            except ValueError:
                pass
        max_order = await db.scalar(
            select(func.coalesce(func.max(Asset.sort_order), 0))
            .where(Asset.project_id == project_id)
        ) or 0

        created = 0
        updated = 0
        unchanged = 0
        reactivated = 0   # retired assets this plugin reports again
        merged_hosts = 0  # cross-connector dedupes (same host, different plugin)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        present_ids: set[str] = set()  # existing asset ids this plugin returned

        for ar in sync_result.assets:
            ek = (ar.external_key or "").strip().lower()
            match = by_key.get(ek) if ek else None
            matched_via_host = False
            if match is None:
                host = _norm_hostname(ar.nom)
                if host:
                    match = by_host.get(host)
                    if match is not None:
                        matched_via_host = True

            if match is None:
                # Create
                max_num += 1
                max_order += 1
                sources = {
                    "keys": {pc.id: ek} if ek else {},
                    "fields": {},
                    "seen": {pc.id: now_iso},
                }
                new_asset = Asset(
                    project_id=project_id,
                    id=f"A-{max_num:03d}",
                    sort_order=max_order,
                    nom=ar.nom or "",
                    type=ar.type or "application",
                    description=ar.description or "",
                    criticite=max(1, min(5, int(ar.criticite or 2))),
                    proprietaire=ar.proprietaire or "",
                    localisation=ar.localisation or "",
                    os=ar.os or "",
                    version=ar.version or "",
                    fournisseur=ar.fournisseur or "",
                    fin_support=ar.fin_support or "",
                    fin_vie=ar.fin_vie or "",
                    statut=ar.statut or "actif",
                    notes=ar.notes or "",
                    ip_address=ar.ip_address or "",
                    depends_on=[],
                    last_login_at=ar.last_login_at,
                    sources=sources,
                )
                # Mark every non-empty connector field as owned by this plugin
                for f in _CONNECTOR_FIELDS:
                    val = getattr(ar, f, None)
                    if val not in (None, ""):
                        sources["fields"][f] = pc.id
                db.add(new_asset)
                if ek:
                    by_key[ek] = new_asset
                h = _norm_hostname(new_asset.nom)
                if h:
                    by_host.setdefault(h, new_asset)
                created += 1
                continue

            # Existing row — merge with priority
            sources = dict(match.sources or {})
            sources.setdefault("keys", {})
            sources.setdefault("fields", {})
            # Record this connector's external_key in the keys map so future
            # syncs from this plugin match via by_key directly.
            if ek and sources["keys"].get(pc.id) != ek:
                sources["keys"][pc.id] = ek
            if matched_via_host:
                merged_hosts += 1

            # This plugin reports the asset → mark it present for reconciliation.
            sources.setdefault("seen", {})[pc.id] = now_iso
            present_ids.add(match.id)

            changed = False
            # Merge each field under the priority rule.
            for f in _CONNECTOR_FIELDS:
                new_val = getattr(ar, f, None)
                if _merge_field(match, f, new_val, pc.id, pc_priority,
                                priority_map, sources):
                    changed = True

            # Notes: append this plugin's scoped notes but never overwrite —
            # other connectors' notes stay visible. Parse existing plugin
            # tags into a set so the dedup check is O(1) instead of O(len(notes)).
            if ar.notes:
                tag = f"[{pc.id}] {ar.notes}"
                note_lines = (match.notes or "").split("\n")
                if tag not in note_lines:
                    match.notes = (match.notes + "\n" + tag) if match.notes else tag
                    changed = True

            # Reappeared after being retired → reactivate. Connector-driven,
            # overrides a prior 'retire' (incl. manual) per product decision.
            # Skip if the connector itself reports an explicit status this run
            # (e.g. CloudTemple "retired") — that value already won the merge.
            if not (ar.statut or "").strip() and match.statut == "retire":
                match.statut = "actif"
                sources.setdefault("fields", {})["statut"] = pc.id
                changed = True
                reactivated += 1

            # Keep SQLAlchemy aware that the JSONB changed.
            match.sources = sources
            if changed:
                match.updated_at = now
                updated += 1
            else:
                unchanged += 1

        # ── Reconciliation: retire assets this plugin used to report but
        # no longer returns (only once no connector still sees them).
        retired = _reconcile_retired(existing, present_ids, pc.id, now)
    except HTTPException:
        raise
    except Exception as upsert_exc:
        await db.rollback()
        logging.getLogger("asset-backend").exception(
            "sync_plugin upsert failed — marking job error")
        # Reload the job in a fresh transaction to persist the error state.
        pc = await db.get(AssetPluginConfig, (project_id, plugin_id))
        job_reload = await db.get(AssetSyncJob, job.id)
        if job_reload is not None:
            job_reload.status = "error"
            job_reload.completed_at = datetime.now(timezone.utc)
            job_reload.error_message = _sanitize_err(upsert_exc, "Upsert failed")[:2000]
        if pc is not None:
            pc.last_sync_at = datetime.now(timezone.utc)
            pc.last_sync_status = "error"
        await db.commit()
        raise HTTPException(status_code=500,
                            detail="Upsert failed — check server logs")

    # Finalise job
    job.status = "success" if not sync_result.errors else "partial"
    job.completed_at = datetime.now(timezone.utc)
    job.assets_found = len(sync_result.assets)
    job.assets_created = created
    job.assets_updated = updated
    job.assets_unchanged = unchanged
    if sync_result.errors:
        logging.getLogger("asset-backend").warning(
            "Plugin %s partial errors: %s", plugin_id, sync_result.errors)
    job.error_message = (f"{len(sync_result.errors)} connector error(s)"
                         if sync_result.errors else "")[:2000]

    pc.last_sync_at = datetime.now(timezone.utc)
    pc.last_sync_status = job.status
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "status": job.status,
        "assets_found": len(sync_result.assets),
        "assets_created": created,
        "assets_updated": updated,
        "assets_unchanged": unchanged,
        "assets_retired": retired,
        "assets_reactivated": reactivated,
        "assets_merged_hosts": merged_hosts,
        "connector_errors_count": len(sync_result.errors or []),
    }


@proj_router.get("/{plugin_id}/history")
async def plugin_history(project_id: uuid.UUID, plugin_id: str,
                         user: Optional[User] = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    await get_project_or_404(project_id, user, db, require_perm="edit")
    result = await db.execute(
        select(AssetSyncJob)
        .where(AssetSyncJob.project_id == project_id,
               AssetSyncJob.plugin_id == plugin_id)
        .order_by(AssetSyncJob.started_at.desc())
        .limit(50)
    )
    return [
        {
            "id": str(j.id),
            "status": j.status,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            "assets_found": j.assets_found,
            "assets_created": j.assets_created,
            "assets_updated": j.assets_updated,
            "assets_unchanged": j.assets_unchanged,
            "error_message": j.error_message or "",
        }
        for j in result.scalars().all()
    ]
