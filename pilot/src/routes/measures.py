"""Measures: aggregate from all modules, sync, write-back."""

from __future__ import annotations

import asyncio
import os
import secrets as _secrets
import uuid
from datetime import datetime, timezone
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin, require_writer
from src.database import get_db
from src.models import MeasureCache, ModuleRegistry, Project, ProjectMeasure, User

router = APIRouter(prefix="/api/measures", tags=["measures"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

_VALID_STATUSES = {"planned", "in_progress", "completed", "backlog"}


def _legacy_source_equiv(source_id: str, entity_id: str, by_source: dict):
    """Find the legacy-format cache row equivalent to a FEAT-32 composite.

    "<entity8>:<local>" matches a row "<local>@<entity_uuid>" with the same
    entity_id (audit's pre-FEAT-32 emitter). Returns None when no legacy
    sibling exists — plain new measures insert normally."""
    if ":" not in source_id:
        return None
    local = source_id.split(":", 1)[1]
    for mc in by_source.values():
        if mc.entity_id == entity_id and mc.source_id == f"{local}@{entity_id}":
            return mc
    return None


@router.get("")
async def list_measures(
    module: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(MeasureCache)
    if module:
        query = query.where(MeasureCache.module == module)
    if status:
        query = query.where(MeasureCache.data["status"].as_string() == status)
    result = await db.execute(query.order_by(MeasureCache.module, MeasureCache.source_id))
    measures = result.scalars().all()

    items = []
    for mc in measures:
        d = mc.data or {}
        items.append({
            "id": str(mc.id),
            "module": mc.module,
            "source_id": mc.source_id,
            "entity_id": mc.entity_id or "",
            "entity_name": mc.entity_name,
            "vendor_id": d.get("vendor_id", ""),
            "vendor_name": d.get("vendor_name", ""),
            "title": d.get("title", ""),
            "description": d.get("description", ""),
            "status": d.get("status", ""),
            "assignee": d.get("assignee", ""),
            "due_date": d.get("due_date", ""),
            "type": d.get("type", ""),
            "progress_log": d.get("progress_log", []),
            "synced_at": mc.synced_at.isoformat() if mc.synced_at else None,
        })
    return items


class MeasureUpdate(BaseModel):
    status: Literal["planned", "in_progress", "completed", "backlog"] | None = None
    assignee: str | None = None
    due_date: str | None = None
    title: str | None = None
    description: str | None = None
    progress_log: list | None = None


class MeasureCreate(BaseModel):
    title: str
    status: Literal["planned", "in_progress", "completed", "backlog"] = "planned"
    assignee: str = ""
    due_date: str = ""
    description: str = ""
    # A native Pilot measure must belong to a remediation project: it stays a
    # transverse (cross-module) measure, not a domain measure that would belong
    # to a module (spec reconciliation, decision B).
    project_id: str = ""


@router.post("", status_code=201)
async def create_measure(
    body: MeasureCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a transverse measure directly in Pilot (module='pilot'), attached
    to a remediation project — native Pilot measures are bounded to projects
    (decision B), so Pilot stays an orchestration layer, not a domain owner."""
    require_writer(user)
    try:
        proj_uuid = uuid.UUID(body.project_id)
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=422, detail="Une mesure Pilot doit être rattachée à un projet de remédiation.")
    project = await db.get(Project, proj_uuid)
    if not project:
        raise HTTPException(status_code=422, detail="Projet de remédiation introuvable.")
    source_id = f"MES-{uuid.uuid4().hex[:8].upper()}"
    data = {
        "source_id": source_id,
        "module": "pilot",
        "title": body.title,
        "description": body.description,
        "status": body.status,
        "assignee": body.assignee,
        "due_date": body.due_date,
        "source_module": "pilot",
    }
    mc = MeasureCache(
        module="pilot", source_id=source_id,
        entity_id="", entity_name="",
        data=data, synced_at=datetime.now(timezone.utc),
    )
    db.add(mc)
    await db.flush()  # assign mc.id before linking it to the project
    db.add(ProjectMeasure(project_id=proj_uuid, measure_id=mc.id))
    await db.commit()
    await db.refresh(mc)
    return {
        "id": str(mc.id), "module": "pilot", "source_id": source_id,
        "title": body.title, "status": body.status,
        "assignee": body.assignee, "due_date": body.due_date,
    }


@router.delete("/{measure_id}", status_code=204)
async def delete_measure(
    measure_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a measure from Pilot. For module measures, write-back the
    deletion to the source module first, then purge the local cache."""
    require_writer(user)
    mc = await db.get(MeasureCache, measure_id)
    if not mc:
        raise HTTPException(status_code=404, detail="Measure not found")

    # Write-back: tell the source module to delete the measure too
    if mc.module != "pilot":
        result = await db.execute(select(ModuleRegistry).where(ModuleRegistry.id == mc.module))
        mod = result.scalar_one_or_none()
        if mod and mod.internal_url:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}
                    resp = await client.delete(
                        mod.internal_url.rstrip("/") + f"/api/internal/measures/{mc.source_id}",
                        headers=headers,
                        params={"entity_id": mc.entity_id} if mc.entity_id else {},
                    )
                    # 404 = already deleted in the module, that's fine
                    if not resp.is_success and resp.status_code != 404:
                        raise HTTPException(status_code=502, detail=f"Module returned {resp.status_code}")
            except httpx.RequestError as e:
                raise HTTPException(status_code=502, detail=f"Module unreachable: {e}")

    from src.models import ProjectMeasure
    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(ProjectMeasure).where(ProjectMeasure.measure_id == mc.id))
    await db.delete(mc)
    await db.commit()


@router.patch("/{measure_id}")
async def update_measure(
    measure_id: uuid.UUID,
    body: MeasureUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_writer(user)
    mc = await db.get(MeasureCache, measure_id)
    if not mc:
        raise HTTPException(status_code=404, detail="Measure not found")

    patch_data = {}
    if body.status is not None:
        patch_data["status"] = body.status
    if body.assignee is not None:
        patch_data["assignee"] = body.assignee
    if body.due_date is not None:
        patch_data["due_date"] = body.due_date
    if body.title is not None:
        patch_data["title"] = body.title
    if body.description is not None:
        patch_data["description"] = body.description
    if body.progress_log is not None:
        patch_data["progress_log"] = body.progress_log

    # Write back to source module (skip for Pilot-native measures)
    if mc.module != "pilot" and patch_data:
        result = await db.execute(select(ModuleRegistry).where(ModuleRegistry.id == mc.module))
        mod = result.scalar_one_or_none()
        if not mod:
            raise HTTPException(status_code=404, detail="Module not found")
        await write_back_measure(mc, patch_data, mod, raise_on_error=True)

    # Update local cache
    data = dict(mc.data or {})
    data.update(patch_data)
    mc.data = data
    mc.synced_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}


async def write_back_measure(mc, patch_data: dict, mod, *, raise_on_error: bool) -> bool:
    """PATCH the source module's measure (FEAT-11 DRY: single write-back used
    by update_measure, projects._cascade_status and the meta-measure
    propagation). Pilot-native measures and unregistered modules are the
    caller's responsibility. Returns True on success; on failure raises
    (raise_on_error) or returns False."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}
            resp = await client.patch(
                mod.internal_url.rstrip("/") + f"/api/internal/measures/{mc.source_id}",
                headers=headers,
                params={"entity_id": mc.entity_id} if mc.entity_id else {},
                json=patch_data,
            )
            if not resp.is_success:
                if raise_on_error:
                    raise HTTPException(status_code=502, detail=f"Module returned {resp.status_code}")
                return False
            return True
    except httpx.RequestError as e:
        if raise_on_error:
            raise HTTPException(status_code=502, detail=f"Module unreachable: {e}")
        import logging
        logging.getLogger("pilot").warning(f"write-back failed for {mc.module}/{mc.source_id}: {e}")
        return False


@router.post("/notify")
async def notify_measure(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Receive a measure upsert from a module. Called by modules after
    a local measure update so Pilot's cache stays in sync without
    waiting for the next full /sync pull."""
    token = request.headers.get("X-Service-Token", "")
    if not SERVICE_TOKEN or not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")
    body = await request.json()
    module = body.get("module", "")
    source_id = body.get("source_id", "")
    if not module or not source_id:
        raise HTTPException(status_code=400, detail="module and source_id required")

    existing = await db.execute(
        select(MeasureCache).where(MeasureCache.module == module, MeasureCache.source_id == source_id)
    )
    mc = existing.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    # Deletion: if the module signals a measure was removed locally,
    # purge it from Pilot's cache + unlink from all projects.
    if body.get("deleted"):
        if mc:
            from src.models import ProjectMeasure
            from sqlalchemy import delete as _sa_del
            await db.execute(_sa_del(ProjectMeasure).where(ProjectMeasure.measure_id == mc.id))
            await db.delete(mc)
        await db.commit()
        return {"ok": True, "action": "deleted"}

    if mc:
        # Merge, not replace: modules send partial payloads on update
        # (only the mutated fields). Replacing would clobber title,
        # description, entity_name, etc. that were set on creation.
        merged = dict(mc.data or {})
        merged.update(body)
        mc.data = merged
        mc.entity_name = body.get("entity_name", mc.entity_name)
        mc.entity_id = body.get("entity_id", mc.entity_id)
        mc.synced_at = now
    else:
        db.add(MeasureCache(
            module=module, source_id=source_id,
            entity_id=body.get("entity_id", ""),
            entity_name=body.get("entity_name", ""),
            data=body, synced_at=now,
        ))
    await db.commit()
    return {"ok": True}


@router.post("/notify-bulk")
async def notify_measures_bulk(request: Request, db: AsyncSession = Depends(get_db)):
    """Batch variant of /notify: upsert (or delete) many measures in ONE
    request + ONE commit. Used by callers that touch many measures at once —
    e.g. a project rename re-labeling every measure — instead of one HTTP
    round-trip and one commit per measure.

    Body: {"entries": [ <same shape as /notify body>, ... ]} (a bare list is
    also accepted). Same merge semantics as /notify for updates."""
    token = request.headers.get("X-Service-Token", "")
    if not SERVICE_TOKEN or not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")
    body = await request.json()
    entries = body.get("entries") if isinstance(body, dict) else body
    if not isinstance(entries, list):
        raise HTTPException(status_code=400, detail="entries must be a list")

    # Load every referenced cache row up front — one query per module present
    # in the batch, instead of a SELECT per entry.
    from collections import defaultdict
    from sqlalchemy import delete as _sa_del

    ids_by_module: dict[str, set] = defaultdict(set)
    valid = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        module = e.get("module", "")
        source_id = e.get("source_id", "")
        if not module or not source_id:
            continue
        ids_by_module[module].add(source_id)
        valid.append(e)

    existing: dict = {}
    for module, ids in ids_by_module.items():
        rows = (await db.execute(
            select(MeasureCache).where(
                MeasureCache.module == module,
                MeasureCache.source_id.in_(list(ids)),
            )
        )).scalars().all()
        for mc in rows:
            existing[(module, mc.source_id)] = mc

    now = datetime.now(timezone.utc)
    added = updated = removed = 0
    for e in valid:
        key = (e["module"], e["source_id"])
        mc = existing.get(key)
        if e.get("deleted"):
            if mc:
                await db.execute(_sa_del(ProjectMeasure).where(ProjectMeasure.measure_id == mc.id))
                await db.delete(mc)
                existing.pop(key, None)
                removed += 1
            continue
        if mc:
            merged = dict(mc.data or {})
            merged.update(e)
            mc.data = merged
            mc.entity_name = e.get("entity_name", mc.entity_name)
            mc.entity_id = e.get("entity_id", mc.entity_id)
            mc.synced_at = now
            updated += 1
        else:
            newmc = MeasureCache(
                module=e["module"], source_id=e["source_id"],
                entity_id=e.get("entity_id", ""),
                entity_name=e.get("entity_name", ""),
                data=e, synced_at=now,
            )
            db.add(newmc)
            existing[key] = newmc
            added += 1

    await db.commit()
    return {"ok": True, "added": added, "updated": updated, "removed": removed}


@router.post("/sync")
async def sync_measures(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Pull measures from all active modules and update the cache."""
    require_admin(user)
    result = await db.execute(select(ModuleRegistry).where(ModuleRegistry.status == "active"))
    modules = result.scalars().all()
    targets = [m for m in modules if m.internal_url]
    headers = {"X-Service-Token": SERVICE_TOKEN}

    # ── Phase 1: fetch every module's measures concurrently over ONE shared
    # client, instead of serially with a fresh client per module (was
    # Σ(latencies); now ~max(latencies)). ──
    async def _fetch(mod):
        try:
            resp = await client.get(
                mod.internal_url.rstrip("/") + "/api/internal/measures", headers=headers
            )
            if not resp.is_success:
                return mod, None, f"HTTP {resp.status_code}"
            return mod, resp.json(), None
        except Exception as e:
            return mod, None, str(e)

    async with httpx.AsyncClient(timeout=15.0) as client:
        fetched = await asyncio.gather(*[_fetch(m) for m in targets])

    report = {m.id: {"skipped": True} for m in modules if not m.internal_url}

    # ── Phase 2: apply to the cache. The DB session is not concurrency-safe,
    # so this stays sequential — but each module's existing rows are loaded
    # ONCE into a dict (no per-measure SELECT), and that same set drives the
    # stale-purge (no second query). ──
    from sqlalchemy import delete as _sa_del
    for mod, measures, err in fetched:
        if err is not None:
            report[mod.id] = {"error": err}
            continue
        # Contract: /api/internal/measures returns a JSON list of measure
        # dicts. Be defensive — a module emitting the wrong shape (dict
        # envelope, null, etc.) must not break the whole sync.
        if not isinstance(measures, list):
            report[mod.id] = {"error": f"bad shape: expected list, got {type(measures).__name__}"}
            continue

        existing_rows = (await db.execute(
            select(MeasureCache).where(MeasureCache.module == mod.id)
        )).scalars().all()
        by_source = {mc.source_id: mc for mc in existing_rows}

        added, updated = 0, 0
        remote_ids = set()
        now = datetime.now(timezone.utc)
        for m in measures:
            if not isinstance(m, dict):
                continue
            source_id = m.get("source_id", "")
            entity_id = m.get("entity_id", "")
            remote_ids.add(source_id)
            mc = by_source.get(source_id)
            if mc is None:
                # FEAT-32 — composite re-key: a module may have switched its
                # source_id format ("<id>@<uuid>" → "<uuid8>:<id>"). Adopt the
                # legacy row in place (same MeasureCache.id) so the project
                # links survive instead of insert-new + purge-old.
                legacy = _legacy_source_equiv(source_id, entity_id, by_source)
                if legacy is not None:
                    remote_ids.discard(source_id)
                    legacy.source_id = source_id
                    by_source[source_id] = legacy
                    remote_ids.add(source_id)
                    mc = legacy
            if mc:
                mc.data = m
                mc.entity_name = m.get("entity_name", "")
                mc.entity_id = entity_id
                mc.synced_at = now
                updated += 1
            else:
                db.add(MeasureCache(
                    module=mod.id, source_id=source_id, entity_id=entity_id,
                    entity_name=m.get("entity_name", ""), data=m, synced_at=now,
                ))
                added += 1

        # Purge measures that no longer exist in the module (reuse existing_rows)
        removed = 0
        for mc in existing_rows:
            if mc.source_id not in remote_ids:
                await db.execute(_sa_del(ProjectMeasure).where(ProjectMeasure.measure_id == mc.id))
                await db.delete(mc)
                removed += 1

        report[mod.id] = {"added": added, "updated": updated, "removed": removed}

    await db.commit()
    # Journal only when the sync actually changed the cache (added/removed):
    # the dashboard auto-refresh calls this every 5 minutes and routine
    # no-op ticks were drowning the activity feed (user feedback).
    changed = {m: {"added": r.get("added", 0), "removed": r.get("removed", 0)}
               for m, r in report.items()
               if isinstance(r, dict) and (r.get("added") or r.get("removed"))}
    if changed:
        from src.audit import log_write
        await log_write(db, user, None, "measures.sync",
                        entity_type="measure_cache", entity_id="",
                        details=changed, commit=True)
    return report
