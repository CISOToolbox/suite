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

Every action on a session names it (the id the agent gave when it opened):
a screen left open must never act on, or close, a session another admin has
opened since, at another instant. A promotion runs in the background; the
screen follows its state rather than holding a request open for its length.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import log_write
from src.auth import get_current_user, require_admin
from src.database import async_session, get_db
from src.models import ModuleRegistry, User

logger = logging.getLogger("pilot.restore")
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
    session: str              # the session the confirmation was given on


class ObjectRestoreBody(BaseModel):
    session: str


# Promotions this process runs, by module: {state: running|done|failed|unknown,
# phase, session, time, started_at, finished_at, by, result, error}. A second
# request while one runs is answered with it — no second export, no second
# backup. "unknown": Pilot lost track of the agent once the promotion was
# asked for; the next status request asks the agent again.
_promotions: dict[str, dict] = {}
_promotion_tasks: set = set()
# Object restores in progress, by module. A promotion and an object restore
# exclude each other: the object written into the live database during a
# switch would be lost, and the safety backup of a promotion must not miss
# a restore under way.
_object_restores: dict[str, int] = {}
# Agent promotion state polling: interval, and how many consecutive failures
# to reach the agent are tolerated before giving up on it.
_PROMOTE_POLL_S = 3.0
_PROMOTE_POLL_MISSES = 20
# How often the session is touched at the agent before the promotion starts.
_KEEPALIVE_S = 60.0
# Closing a session waits for its instance to stop (pg_ctl waits up to 60 s).
_CLOSE_TIMEOUT_S = 90.0


async def _agent(method: str, path: str, body: dict | None = None, timeout: float = 30) -> dict:
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="Recovery agent not configured")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
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


async def _check_session(module: str, session: str) -> dict:
    """The module's agent session, if it is still the one the caller saw.

    Answers 409 when it was closed, expired or reopened since: acting then
    would use another instant than the one the admin chose."""
    try:
        status = await _agent("GET", f"/recover/{module}")
    except HTTPException as e:
        if e.status_code != 404:
            raise
        status = {}
    if not session or status.get("session") != session:
        raise HTTPException(status_code=409, detail=(
            f"restore session changed: the session of '{module}' was closed or reopened "
            f"since this screen opened it — explore again"))
    if status.get("status") == "promoted":
        raise _already_restored(module)
    if status.get("status") != "ready":
        raise HTTPException(status_code=409, detail=f"The restore session of '{module}' is not ready")
    return status


def _already_restored(module: str) -> HTTPException:
    """A session promotes once: again would replace the live database a second
    time, and lose every write made since the first."""
    return HTTPException(status_code=409, detail=(
        f"already restored from this session of '{module}' — open a new one to restore again"))


def _refuse_while_promoting(module: str) -> None:
    """Nothing else on the module while its database is being replaced: a
    write into the live database during the switch would be lost."""
    p = _promotions.get(module)
    if p is not None and p["state"] in ("running", "unknown"):
        raise HTTPException(status_code=409,
                            detail=f"'{module}' is being promoted — wait for it to finish")


def _promotion_view(p: dict) -> dict:
    return {k: p.get(k) for k in ("module", "state", "phase", "session", "time", "started_at",
                                  "finished_at", "by", "result", "error")}


async def _agent_promotion(module: str) -> dict | None:
    """The agent's own state of the module's last promotion, if any."""
    try:
        return await _agent("GET", f"/recover/{module}/promote")
    except HTTPException as e:
        if e.status_code == 404:
            return None
        raise


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
    _refuse_while_promoting(body.module)
    result = await _agent("POST", "/recover", {"module": body.module, "time": body.time})
    await log_write(db, user, None, "restore.explore",
                    entity_type="recovery", entity_id=body.module,
                    details={"time": body.time}, commit=True)
    return result


def _unreadable(status: dict, module: str, detail: str) -> dict:
    logger.warning("restore session %s: module cannot read the restored instance: %s",
                   module, detail)
    return {**status, "status": "unreadable", "error": detail[-300:]}


@router.get("/sessions/{module}")
async def session_status(module: str, user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """Agent status + (when ready) the object list at T merged with the live
    list, sorted by diff likelihood (updated_at mismatch first)."""
    require_admin(user)
    status = await _agent("GET", f"/recover/{module}")
    if status.get("status") != "ready":
        return status

    # The agent has the instance ready; the module must still be able to read
    # it. When it cannot (typically: a point in time before a database
    # password change), say so instead of failing the poll, so the screen can
    # explain what to do — and keep the session, which the operator can fix.
    # Only a failure of the module itself counts: an unreachable or unknown
    # module is a different problem and surfaces as an error, as before.
    if module == "pilot":
        try:
            items_t = await _pilot_recovery_export()
        except Exception as e:  # noqa: BLE001 — reported to the admin, not swallowed
            return _unreadable(status, module, str(e))
    else:
        base = await _module_url(db, module)
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(base + "/api/internal/export-recovery",
                                    headers={"X-Service-Token": SERVICE_TOKEN})
        if resp.status_code >= 500:
            return _unreadable(status, module, f"{resp.status_code}: {resp.text[:200]}")
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"{module}/api/internal/export-recovery"
                                                         f" → {resp.status_code}: {resp.text[:200]}")
        list_t = resp.json()

    if module == "pilot":
        from src.routes.backups import _pilot_self_export
        items_live = await _pilot_self_export(db)
        list_t = [{"id": i["id"], "name": i["name"], "organization": i.get("organization", "")}
                  for i in items_t]
        list_live = [{"id": i["id"], "name": i["name"], "organization": i.get("organization", "")}
                     for i in items_live]
    else:
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
async def object_diff(module: str, item_id: str, session: str = "",
                      user: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    require_admin(user)
    _refuse_while_promoting(module)
    await _check_session(module, session)
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
async def restore_object(module: str, item_id: str, body: ObjectRestoreBody,
                         user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    """N1: bring ONE object back to its state at T. Safety backup first,
    then reinjection through the module's own restore endpoint (server
    validations + module journal), then measures resync."""
    require_admin(user)
    _refuse_while_promoting(module)
    # Registered with no await since the check: a promotion cannot start
    # between the two.
    _object_restores[module] = _object_restores.get(module, 0) + 1
    try:
        status = await _check_session(module, body.session)
        # 1. Safety backup of the CURRENT state (the undo of the restore).
        from src.routes.backups import run_backup
        await run_backup(module_id=module, user=user, db=db)

        # 2. State at T → module restore endpoint. Checked again just before
        # the write: nothing may write into a database being replaced.
        if module == "pilot":
            items_t = await _pilot_recovery_export()
            at_t = next((i for i in items_t if str(i["id"]) == item_id), None)
            if at_t is None:
                raise HTTPException(status_code=404, detail="Object not found at T")
            from src.routes.backups import _pilot_self_restore
            _refuse_while_promoting(module)
            result = await _pilot_self_restore(db, at_t.get("data", {}))
        else:
            at_t = await _module_get(db, module, f"/api/internal/export-recovery/{item_id}")
            _refuse_while_promoting(module)
            result = await _module_put(db, module, f"/api/internal/restore/{item_id}", at_t)
    finally:
        _object_restores[module] -= 1
        if not _object_restores[module]:
            del _object_restores[module]

    # 3. Consolidated action plan follows the module.
    from src.routes.measures import sync_measures
    try:
        await sync_measures(user=user, db=db)
    except Exception:
        pass  # sync failure must not mask a successful restore

    await log_write(db, user, None, "restore.object",
                    entity_type=module, entity_id=item_id,
                    target=at_t.get("name", ""), details={"time": status.get("time")},
                    commit=True)
    return {"ok": True, "module": module, "id": item_id, "result": result}


class _AgentFailed(Exception):
    """The agent ran the promotion and reports it failed: a definitive answer."""


async def _await_agent_promotion(module: str) -> dict:
    """Wait for the agent's promotion to end, however long it takes."""
    misses = 0
    while True:
        await asyncio.sleep(_PROMOTE_POLL_S)
        try:
            p = await _agent_promotion(module)
        except HTTPException:
            misses += 1
            if misses >= _PROMOTE_POLL_MISSES:
                raise
            continue
        misses = 0
        if p is None:
            raise HTTPException(status_code=502, detail=(
                "The backup agent no longer knows this promotion (restarted?)"))
        if p.get("state") == "done":
            return p.get("result") or {}
        if p.get("state") == "failed":
            raise _AgentFailed(str(p.get("error") or "promotion failed"))


async def _keep_session(module: str) -> None:
    """Touch the agent session until cancelled. Before the agent runs the
    promotion it does not protect the session: a safety backup longer than
    what is left of its TTL would otherwise see it expire."""
    while True:
        await asyncio.sleep(_KEEPALIVE_S)
        try:
            await _agent("GET", f"/recover/{module}")
        except HTTPException:
            pass   # the promotion's own session check reports a lost session


async def _finish_promotion(module: str, rec: dict, user: User, result: dict) -> None:
    """The live database was replaced: resync the measures, journal it.

    Never fails: the switch has happened, whatever goes wrong afterwards is
    reported alongside "done", never as a failed promotion."""
    rec["phase"] = "sync"
    warning = None
    try:
        from src.routes.measures import sync_measures
        async with async_session() as db:
            try:
                await sync_measures(user=user, db=db)
            except Exception:
                pass
            await log_write(db, user, None, "restore.module",
                            entity_type=module, entity_id=module,
                            details={**result, "time": rec["time"]}, commit=True)
    except Exception as e:  # noqa: BLE001 — see above
        logger.exception("promotion of %s: journal entry failed", module)
        warning = (f"The database was replaced, but the journal entry could not be written "
                   f"({str(e) or type(e).__name__}).")
    rec.update(state="done", result=result, error=warning, finished_at=time.time())


def _lost_track(rec: dict, detail: str) -> None:
    """Pilot can no longer tell whether the agent replaced the database."""
    rec.update(state="unknown", error=(
        f"Pilot lost track of the promotion ({detail}). The live database may have been "
        f"replaced, or still be being replaced: check the module's data and the backup "
        f"agent before trying again."))


async def _run_promotion(module: str, rec: dict, user: User) -> None:
    """Background task of one promotion: schema check, safety backup, agent
    promotion, measures resync, journal. Its record holds the outcome."""
    keepalive = asyncio.create_task(_keep_session(module))
    try:
        async with async_session() as db:
            # FEAT-29 guard: bring the scratch schema to the module's current
            # head BEFORE the swap (the module's export-recovery list runs
            # alembic upgrade on the scratch). A failed upgrade aborts here —
            # the live db is never touched with a schema the running code
            # cannot read.
            rec["phase"] = "schema"
            try:
                await _module_get(db, module, "/api/internal/export-recovery")
            except HTTPException as e:
                raise HTTPException(status_code=409, detail=(
                    f"Schema upgrade on the recovered state failed — promote refused: {e.detail}"))
            rec["phase"] = "backup"
            from src.routes.backups import run_backup
            await run_backup(module_id=module, user=user, db=db)
        rec["phase"] = "promote"
        rec["requested_at"] = time.time()
        try:
            await _agent("POST", f"/recover/{module}/promote", {"session": rec["session"]})
        except HTTPException as e:
            # Refused by the agent (session changed, already running, rate
            # limit): nothing started. Anything else (timeout, unreachable):
            # it may have started.
            if not 400 <= e.status_code < 500:
                _lost_track(rec, str(e.detail))
                return
            raise
        keepalive.cancel()   # the agent holds the session from here on
        try:
            result = await _await_agent_promotion(module)
        except HTTPException as e:
            _lost_track(rec, str(e.detail))
            return
        await _finish_promotion(module, rec, user, result)
    except _AgentFailed as e:
        rec.update(state="failed", error=str(e))
    except HTTPException as e:
        rec.update(state="failed", error=str(e.detail))
    except Exception as e:  # noqa: BLE001 — reported on the screen, not lost in a task
        logger.exception("promotion of %s failed", module)
        if rec["phase"] in ("promote", "sync"):
            _lost_track(rec, str(e) or type(e).__name__)
        else:
            rec.update(state="failed", error=str(e) or type(e).__name__)
    finally:
        keepalive.cancel()
        if rec["state"] == "failed" and not rec["finished_at"]:
            rec["finished_at"] = time.time()


async def _reconcile(module: str, rec: dict) -> dict:
    """A promotion Pilot lost track of: ask the agent again, and finish it
    (journal included) once the agent says how it ended. While the agent
    cannot answer, it stays unknown."""
    if rec["state"] != "unknown":
        return _promotion_view(rec)
    try:
        theirs = await _agent_promotion(module)
    except HTTPException:
        return _promotion_view(rec)
    ours = (theirs is not None and theirs.get("session") == rec["session"]
            and (theirs.get("started_at") or 0) >= rec.get("requested_at", 0) - 5)
    if rec["state"] != "unknown":   # resolved by a concurrent request meanwhile
        return _promotion_view(rec)
    if not ours:
        # The agent answers and is not running it: it never started, or the
        # agent restarted and lost it. Not promoting now, state of the data
        # to check.
        rec.update(state="failed", finished_at=time.time())
        return _promotion_view(rec)
    if theirs["state"] == "running":
        return {**_promotion_view(rec), "state": "running", "phase": "promote"}
    if theirs["state"] == "failed":
        rec.update(state="failed", error=str(theirs.get("error") or "promotion failed"),
                   finished_at=time.time())
        return _promotion_view(rec)
    rec["state"] = "running"    # claimed: a concurrent request will not finish it twice
    try:
        await _finish_promotion(module, rec, rec["_user"], theirs.get("result") or {})
    except BaseException:
        # Interrupted (request cancelled): give the claim back, the next
        # read finishes it — never leave it "running" with nobody on it.
        if rec["state"] == "running":
            rec["state"] = "unknown"
        raise
    return _promotion_view(rec)


@router.post("/sessions/{module}/promote", status_code=202)
async def promote_module(module: str, body: PromoteBody,
                         user: User = Depends(get_current_user)):
    """N2: replace the WHOLE live database of the module with the state at T.
    Typed confirmation + safety backup are mandatory. Starts the promotion in
    the background and answers its state; follow it on GET …/promote. Expect
    a few seconds of 500s on the module while its pool reconnects."""
    require_admin(user)
    if body.confirm != module:
        raise HTTPException(status_code=400,
                            detail="Confirmation mismatch: type the module name to confirm")
    if module == "pilot":
        raise HTTPException(status_code=400,
                            detail="Pilot N2 must follow the DBA runbook (it hosts this very API)")
    # Already running (a reload, another tab, a retry): show it, start nothing.
    # One Pilot lost track of: never start another before knowing how it ended.
    # Resolved here, it is answered and nothing new starts: the admin confirmed
    # a promotion that was, as it turns out, already done (or failed).
    current = _promotions.get(module)
    if current is not None and current["state"] == "unknown":
        view = await _reconcile(module, current)
        if view["state"] == "unknown":
            raise HTTPException(status_code=409, detail=view["error"])
        if view["state"] == "failed":
            raise HTTPException(status_code=409, detail=(
                f"The previous promotion of '{module}' failed: {view['error']} — check the "
                f"module, then confirm again to retry"))
        return JSONResponse(status_code=200 if view["state"] == "done" else 202, content=view)
    if current is not None and current["state"] == "running":
        return _promotion_view(current)
    if current is not None and current["state"] == "done" and current["session"] == body.session:
        raise _already_restored(module)
    if _object_restores.get(module):
        raise HTTPException(status_code=409, detail=(
            f"an object of '{module}' is being restored — wait for it to finish"))
    # Claimed before the first await: two requests cannot both get past here.
    rec = {"module": module, "state": "running", "phase": "checking", "session": body.session,
           "time": None, "started_at": time.time(), "finished_at": None,
           "by": getattr(user, "email", None) if user else None, "result": None, "error": None,
           "_user": user}
    _promotions[module] = rec
    try:
        # One the agent runs without this process knowing (Pilot restarted).
        theirs = await _agent_promotion(module)
        if theirs is not None and theirs.get("state") == "running":
            del _promotions[module]
            return {**theirs, "phase": "promote", "by": None}
        # Done by the agent for this session, whatever Pilot remembers of it
        # (Pilot restarted, another process).
        if theirs is not None and theirs.get("state") == "done" \
                and theirs.get("session") == body.session:
            raise _already_restored(module)
        rec["time"] = (await _check_session(module, body.session)).get("time")
    except BaseException:
        if _promotions.get(module) is rec:
            del _promotions[module]
        raise
    task = asyncio.create_task(_run_promotion(module, rec, user))
    _promotion_tasks.add(task)
    task.add_done_callback(_promotion_tasks.discard)
    return _promotion_view(rec)


@router.get("/sessions/{module}/promote")
async def promotion_status(module: str, user: User = Depends(get_current_user)):
    """State of the module's last promotion: this process's, else the agent's."""
    require_admin(user)
    rec = _promotions.get(module)
    if rec is not None:
        return await _reconcile(module, rec)
    theirs = await _agent_promotion(module)
    if theirs is None:
        raise HTTPException(status_code=404, detail="No promotion")
    return {**theirs, "phase": "promote" if theirs.get("state") == "running" else None, "by": None}


@router.delete("/sessions/{module}")
async def close_session(module: str, session: str = "", user: User = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    """Close the module's session — only the named one when `session` is
    given (a screen closing what it opened). Without it, whichever is open:
    the explicit "close the other session" choice."""
    require_admin(user)
    _refuse_while_promoting(module)
    path = f"/recover/{module}" + (f"?session={quote(session)}" if session else "")
    # Stopping the restored instance can take up to a minute (pg_ctl stop).
    result = await _agent("DELETE", path, timeout=_CLOSE_TIMEOUT_S)
    await log_write(db, user, None, "restore.close",
                    entity_type="recovery", entity_id=module, commit=True)
    return result
