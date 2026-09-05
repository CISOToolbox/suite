"""Point-in-time restore orchestration (FEAT-30 phase 2, stage 3).

Pilot drives the backup agent's recovery API and the modules' recovery
export endpoints to let an admin restore ONE object as it was at instant T
(N1 — no downtime) or a whole module (N2 — guarded), with:
  - automatic safety backup before any write (the "undo of the restore"),
  - reinjection through the module's own /api/internal/restore (server
    validations + module-side journal entry, actor=pilot),
  - measures resync so the consolidated action plan stays coherent,
  - a Pilot audit_log entry for every exploration and restore.

Admin-only. The agent API is reachable only on the compose network and
authenticated with BACKUP_AGENT_TOKEN.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import log_write
from src.auth import get_current_user, require_admin
from src.database import get_db
from src.models import ModuleRegistry, User

router = APIRouter(prefix="/api/restore", tags=["restore"])

AGENT_URL = os.getenv("BACKUP_AGENT_URL", "http://backup-agent:9090")
AGENT_TOKEN = os.getenv("BACKUP_AGENT_TOKEN", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

# Modules the restore UI can target. Pilot itself is handled in-process
# (no HTTP loopback) — see _pilot_* branches below.
RESTORABLE = ("risk", "vendor", "compliance", "audit", "asset", "access",
              "surface", "appsec", "watch", "pilot")


class SessionCreate(BaseModel):
    module: str
    time: str | None = None   # ISO timestamp; None = latest


class PromoteBody(BaseModel):
    confirm: str              # must equal the module name (typed confirmation)


async def _agent(method: str, path: str, body: dict | None = None) -> dict:
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="Recovery agent not configured")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(
                method, AGENT_URL.rstrip("/") + path,
                headers={"X-Agent-Token": AGENT_TOKEN},
                json=body)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Agent unreachable: {e}")
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise HTTPException(status_code=resp.status_code, detail=str(detail)[:300])
    return resp.json()


async def _module_url(db: AsyncSession, module: str) -> str:
    result = await db.execute(select(ModuleRegistry).where(ModuleRegistry.id == module))
    mod = result.scalar_one_or_none()
    if not mod or not mod.internal_url:
        raise HTTPException(status_code=404, detail=f"Module {module} not registered")
    return mod.internal_url.rstrip("/")


async def _module_get(db: AsyncSession, module: str, path: str) -> Any:
    base = await _module_url(db, module)
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.get(base + path, headers={"X-Service-Token": SERVICE_TOKEN})
    if resp.status_code >= 400:
        raise HTTPException(status_code=502,
                            detail=f"{module}{path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


async def _module_put(db: AsyncSession, module: str, path: str, body: dict) -> Any:
    base = await _module_url(db, module)
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.put(base + path, headers={"X-Service-Token": SERVICE_TOKEN}, json=body)
    if resp.status_code >= 400:
        raise HTTPException(status_code=502,
                            detail=f"{module}{path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


# ── Pilot-on-pilot (in-process, no HTTP loopback) ─────────────────────

async def _pilot_recovery_export() -> list[dict]:
    from src.backup_common import recovery_session, upgrade_recovery_schema
    from src.routes.backups import _pilot_self_export
    upgrade_recovery_schema()
    async with recovery_session() as rdb:
        return await _pilot_self_export(rdb)


# ── Diff helpers ───────────────────────────────────────────────────────

def _collections(item: dict) -> dict[str, list]:
    """Every list-valued collection of an export item (data.* + root lists
    like audit's measures)."""
    out: dict[str, list] = {}
    data = item.get("data")
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                out[k] = v
    for k, v in item.items():
        if k != "data" and isinstance(v, list):
            out[k] = v
    return out


def _diff_summary(at_t: dict, live: dict | None) -> dict:
    """Per-collection added/removed/changed counts between the state at T
    and the live state. Items are matched by their 'id' when present."""
    cols_t = _collections(at_t)
    cols_l = _collections(live or {})
    rows = []
    identical = True
    for key in sorted(set(cols_t) | set(cols_l)):
        lt, ll = cols_t.get(key, []), cols_l.get(key, [])

        def by_id(lst):
            return {str(e.get("id")): e for e in lst
                    if isinstance(e, dict) and e.get("id") is not None}
        dt, dl = by_id(lt), by_id(ll)
        if dt or dl:
            removed_since_t = len(set(dt) - set(dl))   # present at T, gone now
            added_since_t = len(set(dl) - set(dt))     # created after T
            changed = sum(1 for i in set(dt) & set(dl)
                          if json.dumps(dt[i], sort_keys=True) != json.dumps(dl[i], sort_keys=True))
        else:  # id-less lists: coarse comparison
            removed_since_t = max(0, len(lt) - len(ll))
            added_since_t = max(0, len(ll) - len(lt))
            changed = 0 if lt == ll else min(len(lt), len(ll))
        if removed_since_t or added_since_t or changed or len(lt) != len(ll):
            identical = False

        def _label(e: dict) -> str:
            for f in ("name", "nom", "title", "titre", "mesure", "description", "label"):
                v = e.get(f)
                if v:
                    return str(v)[:80]
            return str(e.get("id", "?"))[:80]
        examples = {}
        if dt or dl:
            examples = {
                "removed": [_label(dt[i]) for i in sorted(set(dt) - set(dl))[:5]],
                "added": [_label(dl[i]) for i in sorted(set(dl) - set(dt))[:5]],
                "changed": [_label(dt[i]) for i in sorted(set(dt) & set(dl))
                            if json.dumps(dt[i], sort_keys=True) != json.dumps(dl[i], sort_keys=True)][:5],
            }
        rows.append({"collection": key, "at_t": len(lt), "live": len(ll),
                     "removed_since_t": removed_since_t,
                     "added_since_t": added_since_t, "changed": changed,
                     "examples": examples})
    return {"identical": identical, "collections": rows,
            "magnitude": sum(r["removed_since_t"] + r["changed"] for r in rows)}


async def _module_journal(db: AsyncSession, module: str, entity_id: str = "", limit: int = 30) -> list:
    """Recent write-journal of a module (who/what/when). Pilot reads its own
    audit_log in-process; other modules serve /api/internal/journal."""
    if module == "pilot":
        from src.models import AuditLog
        q = select(AuditLog).order_by(AuditLog.logged_at.desc()).limit(min(max(limit, 1), 100))
        if entity_id:
            q = q.where(AuditLog.entity_id == entity_id)
        rows = (await db.execute(q)).scalars().all()
        return [{"logged_at": r.logged_at.isoformat() if r.logged_at else None,
                 "user_email": r.user_email or "", "action": r.action or "",
                 "target": r.target or "", "entity_id": r.entity_id or "",
                 "details": (r.details or "")[:300]} for r in rows]
    path = f"/api/internal/journal?limit={int(limit)}"
    if entity_id:
        path += f"&entity_id={entity_id}"
    try:
        return await _module_get(db, module, path)
    except HTTPException:
        return []   # module without journal endpoint (older image)


# ── Routes ─────────────────────────────────────────────────────────────

@router.get("/window")
async def restore_window(user: User = Depends(get_current_user)):
    require_admin(user)
    return await _agent("GET", "/window")


@router.post("/sessions", status_code=202)
async def create_session(body: SessionCreate, user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    require_admin(user)
    if body.module not in RESTORABLE:
        raise HTTPException(status_code=400, detail=f"Invalid module: {body.module}")
    result = await _agent("POST", "/recover", {"module": body.module, "time": body.time})
    await log_write(db, user, None, "restore.explore",
                    entity_type="recovery", entity_id=body.module,
                    details={"time": body.time}, commit=True)
    return result


@router.get("/sessions/{module}")
async def session_status(module: str, user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """Agent status + (when ready) the object list at T merged with the live
    list, sorted by diff likelihood (updated_at mismatch first)."""
    require_admin(user)
    status = await _agent("GET", f"/recover/{module}")
    if status.get("status") != "ready":
        return status

    if module == "pilot":
        items_t = await _pilot_recovery_export()
        from src.routes.backups import _pilot_self_export
        items_live = await _pilot_self_export(db)
        list_t = [{"id": i["id"], "name": i["name"], "organization": i.get("organization", "")}
                  for i in items_t]
        list_live = [{"id": i["id"], "name": i["name"], "organization": i.get("organization", "")}
                     for i in items_live]
    else:
        list_t = await _module_get(db, module, "/api/internal/export-recovery")
        list_live = await _module_get(db, module, "/api/internal/export")

    live_by_id = {str(i["id"]): i for i in list_live}
    t_by_id = {str(i["id"]): i for i in list_t}
    objects = []
    for oid, it in t_by_id.items():
        lv = live_by_id.get(oid)
        objects.append({
            "id": oid,
            "name": it.get("name", ""),
            "organization": it.get("organization", ""),
            "missing_live": lv is None,                    # deleted since T
            "updated_at_t": it.get("updated_at"),
            "updated_at_live": (lv or {}).get("updated_at"),
            "suspect": lv is None or it.get("updated_at") != (lv or {}).get("updated_at"),
        })
    for oid, lv in live_by_id.items():
        if oid not in t_by_id:
            objects.append({"id": oid, "name": lv.get("name", ""),
                            "organization": lv.get("organization", ""),
                            "missing_live": False, "created_after_t": True,
                            "suspect": False})
    objects.sort(key=lambda o: (not o.get("missing_live", False), not o.get("suspect", False)))
    status["objects"] = objects
    return status


@router.get("/journal/{module}")
async def module_journal(module: str, entity_id: str = "", limit: int = 30,
                         user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """Recent writes of the module (event picker for the restore UI)."""
    require_admin(user)
    if module not in RESTORABLE:
        raise HTTPException(status_code=400, detail=f"Invalid module: {module}")
    return await _module_journal(db, module, entity_id=entity_id, limit=limit)


@router.get("/sessions/{module}/objects/{item_id}/diff")
async def object_diff(module: str, item_id: str, user: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    require_admin(user)
    if module == "pilot":
        items_t = await _pilot_recovery_export()
        from src.routes.backups import _pilot_self_export
        items_live = await _pilot_self_export(db)
        at_t = next((i for i in items_t if str(i["id"]) == item_id), None)
        live = next((i for i in items_live if str(i["id"]) == item_id), None)
    else:
        at_t = await _module_get(db, module, f"/api/internal/export-recovery/{item_id}")
        try:
            live = await _module_get(db, module, f"/api/internal/export/{item_id}")
        except HTTPException:
            live = None   # deleted since T
    if at_t is None:
        raise HTTPException(status_code=404, detail="Object not found at T")
    return {"id": item_id, "name": at_t.get("name", ""),
            "exists_live": live is not None,
            "diff": _diff_summary(at_t, live),
            "journal": await _module_journal(db, module, entity_id=item_id, limit=10)}


@router.post("/sessions/{module}/objects/{item_id}/restore")
async def restore_object(module: str, item_id: str, user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """N1: bring ONE object back to its state at T. Safety backup first,
    then reinjection through the module's own restore endpoint (server
    validations + module journal), then measures resync."""
    require_admin(user)
    # 1. Safety backup of the CURRENT state (the undo of the restore).
    from src.routes.backups import run_backup
    await run_backup(module_id=module, user=user, db=db)

    # 2. State at T → module restore endpoint.
    if module == "pilot":
        items_t = await _pilot_recovery_export()
        at_t = next((i for i in items_t if str(i["id"]) == item_id), None)
        if at_t is None:
            raise HTTPException(status_code=404, detail="Object not found at T")
        from src.routes.backups import _pilot_self_restore
        result = await _pilot_self_restore(db, at_t.get("data", {}))
    else:
        at_t = await _module_get(db, module, f"/api/internal/export-recovery/{item_id}")
        result = await _module_put(db, module, f"/api/internal/restore/{item_id}", at_t)

    # 3. Consolidated action plan follows the module.
    from src.routes.measures import sync_measures
    try:
        await sync_measures(user=user, db=db)
    except Exception:
        pass  # sync failure must not mask a successful restore

    await log_write(db, user, None, "restore.object",
                    entity_type=module, entity_id=item_id,
                    target=at_t.get("name", ""), commit=True)
    return {"ok": True, "module": module, "id": item_id, "result": result}


@router.post("/sessions/{module}/promote")
async def promote_module(module: str, body: PromoteBody,
                         user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """N2: replace the WHOLE live database of the module with the state at T.
    Typed confirmation + safety backup are mandatory. Expect a few seconds
    of 500s on the module while its pool reconnects."""
    require_admin(user)
    if body.confirm != module:
        raise HTTPException(status_code=400,
                            detail="Confirmation mismatch: type the module name to confirm")
    if module == "pilot":
        raise HTTPException(status_code=400,
                            detail="Pilot N2 must follow the DBA runbook (it hosts this very API)")
    # FEAT-29 guard: bring the scratch schema to the module's current head
    # BEFORE the swap (the module's export-recovery list runs alembic upgrade
    # on the scratch). A failed upgrade aborts here — the live db is never
    # touched with a schema the running code cannot read.
    try:
        await _module_get(db, module, "/api/internal/export-recovery")
    except HTTPException as e:
        raise HTTPException(status_code=409,
                            detail=f"Schema upgrade on the recovered state failed — promote refused: {e.detail}")
    from src.routes.backups import run_backup
    await run_backup(module_id=module, user=user, db=db)
    result = await _agent("POST", f"/recover/{module}/promote")
    from src.routes.measures import sync_measures
    try:
        await sync_measures(user=user, db=db)
    except Exception:
        pass
    await log_write(db, user, None, "restore.module",
                    entity_type=module, entity_id=module, details=result, commit=True)
    return {"ok": True, "module": module, "result": result}


@router.delete("/sessions/{module}")
async def close_session(module: str, user: User = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    require_admin(user)
    result = await _agent("DELETE", f"/recover/{module}")
    await log_write(db, user, None, "restore.close",
                    entity_type="recovery", entity_id=module, commit=True)
    return result
