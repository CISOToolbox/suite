"""Evidences: consolidated cross-module registry (FEAT-08).

Twin of measures.py — EvidenceCache fed by each module's
GET /api/internal/evidences (pull, /sync) and /api/evidences/notify (push).
"""
from __future__ import annotations

import os
import secrets as _secrets
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin, require_writer
from src.database import get_db
from src.models import EvidenceCache, ModuleRegistry, User

router = APIRouter(prefix="/api/evidences", tags=["evidences"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


@router.get("")
async def list_evidences(
    module: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Consolidated evidence registry (one flat row per cached evidence)."""
    q = select(EvidenceCache)
    if module:
        q = q.where(EvidenceCache.module == module)
    if status:
        q = q.where(EvidenceCache.status == status)
    rows = (await db.execute(q.order_by(EvidenceCache.module, EvidenceCache.source_id))).scalars().all()
    return [
        {
            # Module-pushed payload first, then authoritative server-owned keys
            # last so a module cannot spoof another's identity/status in the
            # consolidated CISO view.
            **(e.data or {}),
            "cache_id": str(e.id), "module": e.module, "source_id": e.source_id,
            "entity_id": e.entity_id, "entity_name": e.entity_name,
            "status": e.status, "synced_at": e.synced_at,
        }
        for e in rows
    ]


class EvidenceUpdate(BaseModel):
    """Fields editable from the consolidated registry (BUG-23 / FEAT-08).
    Pilot fans the edit out to the owning module's internal endpoint."""
    label: str | None = None
    url: str | None = None
    owner: str | None = None
    date_obtention: str | None = None
    date_expiration: str | None = None
    commentaire: str | None = None
    tags: list | None = None


@router.patch("/{module}/{source_id}")
async def update_evidence(
    module: str,
    source_id: str,
    body: EvidenceUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Edit an evidence from the CISO registry: fan the change out to the
    owning module's ``PATCH /api/internal/evidences/{source_id}`` (the module
    stays authoritative/validator), then refresh Pilot's cache from the
    returned payload. Modules without that endpoint yield a clear 400."""
    require_writer(user)
    ec = (await db.execute(
        select(EvidenceCache).where(
            EvidenceCache.module == module, EvidenceCache.source_id == source_id)
    )).scalar_one_or_none()
    if not ec:
        raise HTTPException(status_code=404, detail="Evidence not found")
    mod = (await db.execute(
        select(ModuleRegistry).where(ModuleRegistry.id == module)
    )).scalar_one_or_none()
    if not mod or not mod.internal_url:
        raise HTTPException(status_code=400, detail=f"Module '{module}' not reachable")

    payload = body.model_dump(exclude_unset=True)
    payload["project_id"] = ec.entity_id or ""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.patch(
                mod.internal_url.rstrip("/") + f"/api/internal/evidences/{source_id}",
                json=payload, headers={"X-Service-Token": SERVICE_TOKEN})
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Module unreachable: {e}")
    if resp.status_code in (404, 405, 501):
        raise HTTPException(status_code=400,
                            detail=f"Module '{module}' does not support editing this evidence")
    if not resp.is_success:
        raise HTTPException(status_code=resp.status_code,
                            detail=f"Module rejected the update: {resp.text[:200]}")
    updated = resp.json()
    ec.data = updated
    ec.entity_name = updated.get("entity_name", ec.entity_name)
    ec.status = updated.get("status", ec.status)
    ec.synced_at = datetime.now(timezone.utc)
    await db.commit()
    return {
        **updated,
        "cache_id": str(ec.id), "module": ec.module, "source_id": ec.source_id,
        "entity_id": ec.entity_id, "entity_name": ec.entity_name,
        "status": ec.status, "synced_at": ec.synced_at,
    }


def _check_token(request: Request) -> None:
    token = request.headers.get("X-Service-Token", "")
    if not SERVICE_TOKEN or not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


@router.post("/notify")
async def notify_evidence(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive an evidence upsert/delete push from a module (service-token)."""
    _check_token(request)
    body = await request.json()
    module = body.get("module", "") or body.get("source_module", "")
    source_id = body.get("source_id", "")
    if not module or not source_id:
        raise HTTPException(status_code=400, detail="module and source_id required")

    existing = (await db.execute(
        select(EvidenceCache).where(EvidenceCache.module == module, EvidenceCache.source_id == source_id)
    )).scalar_one_or_none()

    if body.get("deleted"):
        if existing:
            await db.delete(existing)
            await db.commit()
        return {"ok": True, "deleted": True}

    now = datetime.now(timezone.utc)
    if existing:
        existing.data = body
        existing.entity_id = body.get("entity_id", "")
        existing.entity_name = body.get("entity_name", "")
        existing.status = body.get("status", "")
        existing.synced_at = now
    else:
        db.add(EvidenceCache(
            module=module, source_id=source_id,
            entity_id=body.get("entity_id", ""), entity_name=body.get("entity_name", ""),
            status=body.get("status", ""), data=body, synced_at=now,
        ))
    await db.commit()
    return {"ok": True}


@router.post("/sync")
async def sync_evidences(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Pull evidences from every active module's /api/internal/evidences.

    Modules that don't own evidences simply return 404 → skipped."""
    require_admin(user)
    modules = (await db.execute(
        select(ModuleRegistry).where(ModuleRegistry.status == "active"))).scalars().all()
    report: dict = {}
    for mod in modules:
        if not mod.internal_url:
            report[mod.id] = {"skipped": True}
            continue
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    mod.internal_url.rstrip("/") + "/api/internal/evidences",
                    headers={"X-Service-Token": SERVICE_TOKEN})
                if resp.status_code == 404:
                    report[mod.id] = {"skipped": "no evidences endpoint"}
                    continue
                if not resp.is_success:
                    report[mod.id] = {"error": f"HTTP {resp.status_code}"}
                    continue
                evidences = resp.json()
        except Exception as e:  # noqa: BLE001
            report[mod.id] = {"error": str(e)}
            continue
        if not isinstance(evidences, list):
            report[mod.id] = {"error": "bad shape: expected list"}
            continue

        added = updated = 0
        remote_ids: set = set()
        now = datetime.now(timezone.utc)
        for ev in evidences:
            if not isinstance(ev, dict):
                continue
            sid = ev.get("source_id", "")
            remote_ids.add(sid)
            existing = (await db.execute(
                select(EvidenceCache).where(EvidenceCache.module == mod.id, EvidenceCache.source_id == sid)
            )).scalar_one_or_none()
            if existing:
                existing.data = ev
                existing.entity_id = ev.get("entity_id", "")
                existing.entity_name = ev.get("entity_name", "")
                existing.status = ev.get("status", "")
                existing.synced_at = now
                updated += 1
            else:
                db.add(EvidenceCache(
                    module=mod.id, source_id=sid, entity_id=ev.get("entity_id", ""),
                    entity_name=ev.get("entity_name", ""), status=ev.get("status", ""),
                    data=ev, synced_at=now,
                ))
                added += 1
        removed = 0
        for ec in (await db.execute(
                select(EvidenceCache).where(EvidenceCache.module == mod.id))).scalars().all():
            if ec.source_id not in remote_ids:
                await db.delete(ec)
                removed += 1
        report[mod.id] = {"added": added, "updated": updated, "removed": removed}

    await db.commit()
    return {"ok": True, "report": report}
