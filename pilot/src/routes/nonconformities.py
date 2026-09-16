"""Consolidated register of non-conformities and derogations.

Pilot owns nothing here: every record lives in the module that carries it.
The register is read live from each active module's service-token endpoints
(`/api/internal/nonconformities`, `/api/internal/derogations`), decisions and
declarations are relayed to the module with the Pilot user as actor, and the
per-module derogation settings are read and written the same way.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from urllib.parse import quote

from src.auth import SERVICE_TOKEN, get_current_user, require_admin, require_writer
from src.database import get_db
from src.models import ModuleRegistry, User

logger = logging.getLogger("pilot.nonconformities")

router = APIRouter(prefix="/api", tags=["nonconformities"])

# Tests inject an httpx transport here; production leaves it to httpx.
_TRANSPORT: Optional[httpx.AsyncBaseTransport] = None
_TIMEOUT = 10.0


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=_TIMEOUT, transport=_TRANSPORT)


def _headers() -> dict:
    return {"X-Service-Token": SERVICE_TOKEN} if SERVICE_TOKEN else {}


async def _active_modules(db: AsyncSession) -> list[ModuleRegistry]:
    rows = (await db.execute(select(ModuleRegistry).where(ModuleRegistry.status == "active"))).scalars().all()
    return [m for m in rows if m.internal_url and m.id != "pilot"]


def _actor(user: Optional[User]) -> str:
    if user is None:
        return "pilot"
    return (getattr(user, "name", None) or getattr(user, "email", None) or "pilot")[:255]


def module_link(mod: ModuleRegistry, kind: str = "", record_id: str = "") -> str:
    """Deep link into the module's register; with a record, its detail opens
    on load (`?nc=<id>` or `?der=<id>`, consumed by the register panel)."""
    base = (mod.external_url or "").rstrip("/") + "/"
    if kind and record_id:
        base += "?" + ("nc" if kind == "nonconformities" else "der") + "=" + str(record_id)
    return base + "#nonconformities"


async def fetch_register(db: AsyncSession, kind: str, status: Optional[str] = None) -> tuple[list[dict], dict]:
    """Every module's items of `kind` ("nonconformities" | "derogations"),
    fetched concurrently, each stamped with its module and a deep link.
    Returns (items, errors-by-module). A module without the endpoint (404)
    is simply not part of the register."""
    modules = await _active_modules(db)
    items: list[dict] = []
    errors: dict = {}

    async def one(client: httpx.AsyncClient, mod: ModuleRegistry) -> None:
        url = mod.internal_url.rstrip("/") + "/api/internal/" + kind
        params = {"status": status} if status else None
        try:
            resp = await client.get(url, headers=_headers(), params=params)
        except Exception as e:  # noqa: BLE001 — one module never takes the register down
            errors[mod.id] = str(e)[:200]
            return
        if resp.status_code == 404:
            return
        if not resp.is_success:
            errors[mod.id] = f"HTTP {resp.status_code}"
            return
        try:
            payload = resp.json()
        except ValueError:
            errors[mod.id] = "bad payload"
            return
        for it in (payload.get("items") if isinstance(payload, dict) else payload) or []:
            if not isinstance(it, dict):
                continue
            it["module"] = mod.id
            it["module_name"] = mod.name
            it["module_url"] = module_link(mod, kind, str(it.get("id") or ""))
            items.append(it)

    async with _client() as client:
        await asyncio.gather(*(one(client, m) for m in modules), return_exceptions=True)
    items.sort(key=lambda it: str(it.get("created_at") or ""), reverse=True)
    return items, errors


async def _module_or_404(db: AsyncSession, module_id: str) -> ModuleRegistry:
    mod = await db.get(ModuleRegistry, module_id)
    if mod is None or mod.status != "active" or not mod.internal_url:
        raise HTTPException(status_code=404, detail="Unknown or inactive module")
    return mod


async def _relay(mod: ModuleRegistry, method: str, path: str, body: Optional[dict] = None) -> Any:
    """One call to a module's internal route; the module's own status and
    message come back unchanged (a 409 there is a 409 here)."""
    url = mod.internal_url.rstrip("/") + "/api/internal/" + path
    try:
        async with _client() as client:
            resp = await client.request(method, url, headers=_headers(), json=body)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"{mod.id}: {str(e)[:200]}")
    if resp.status_code in (404, 405):
        # No such route on the module: it keeps no register (or not this record).
        raise HTTPException(status_code=404, detail=f"{mod.id}: no register, or unknown record")
    if not resp.is_success:
        detail: Any = resp.text[:500]
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                detail = payload.get("detail", detail)
        except ValueError:
            pass
        raise HTTPException(status_code=resp.status_code if resp.status_code in (400, 409, 422) else 502,
                            detail=detail)
    try:
        return resp.json()
    except ValueError:
        return None


# ── read ─────────────────────────────────────────────────────────────────

@router.get("/nonconformities")
async def list_nonconformities(status: Optional[str] = None, module: Optional[str] = None,
                               user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    items, errors = await fetch_register(db, "nonconformities", status)
    if module:
        items = [it for it in items if it.get("module") == module]
    return {"items": items, "total": len(items), "errors": errors}


@router.get("/derogations")
async def list_derogations(status: Optional[str] = None, module: Optional[str] = None,
                           user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    items, errors = await fetch_register(db, "derogations", status)
    if module:
        items = [it for it in items if it.get("module") == module]
    return {"items": items, "total": len(items), "errors": errors}


# ── relayed writes ───────────────────────────────────────────────────────

class DecisionBody(BaseModel):
    approve: bool
    note: str = ""


class DeclarationBody(BaseModel):
    module: str
    title: str = Field(min_length=3, max_length=500)
    description: str = ""
    source: str = "observation"
    severity: str = "medium"
    observed_at: Optional[str] = None
    observed_by: str = ""
    domain: str = ""
    requirement_ref: str = ""
    evidence: list = Field(default_factory=list)


class SettingsBody(BaseModel):
    max_derogation_days: int = Field(ge=1, le=3650)


@router.post("/derogations/{module}/{der_id}/decision")
async def decide_derogation(module: str, der_id: str, body: DecisionBody,
                            user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Approval or refusal decided in Pilot, applied by the module."""
    require_admin(user)
    mod = await _module_or_404(db, module)
    return await _relay(mod, "POST", f"derogations/{quote(der_id, safe='')}/decision",
                        {"approve": body.approve, "note": body.note, "actor": _actor(user)})


@router.post("/nonconformities", status_code=201)
async def declare_nonconformity(body: DeclarationBody, user: User = Depends(get_current_user),
                                db: AsyncSession = Depends(get_db)):
    """A non-conformity declared from the console, created in the module it belongs to."""
    require_writer(user)
    mod = await _module_or_404(db, body.module)
    payload = body.model_dump(exclude={"module"})
    payload["actor"] = _actor(user)
    payload["observed_by"] = body.observed_by or _actor(user)
    out = await _relay(mod, "POST", "nonconformities", payload)
    if isinstance(out, dict):
        out["module"] = mod.id
        out["module_name"] = mod.name
        out["module_url"] = module_link(mod, "nonconformities", str(out.get("id") or ""))
    return out


# ── settings ─────────────────────────────────────────────────────────────

@router.get("/nonconformities-settings")
async def list_settings(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """The maximum derogation duration of every module that keeps a register."""
    modules = await _active_modules(db)
    out: list[dict] = []

    async def one(client: httpx.AsyncClient, mod: ModuleRegistry) -> None:
        url = mod.internal_url.rstrip("/") + "/api/internal/nonconformities-settings"
        try:
            resp = await client.get(url, headers=_headers())
        except httpx.HTTPError:
            return
        if not resp.is_success:
            return
        try:
            data = resp.json()
        except ValueError:
            return
        out.append({"module": mod.id, "module_name": mod.name,
                    "max_derogation_days": int(data.get("max_derogation_days") or 0)})

    async with _client() as client:
        await asyncio.gather(*(one(client, m) for m in modules))
    out.sort(key=lambda r: r["module"])
    return {"items": out}


@router.put("/nonconformities-settings/{module}")
async def put_settings(module: str, body: SettingsBody, user: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    require_admin(user)
    mod = await _module_or_404(db, module)
    return await _relay(mod, "PUT", "nonconformities-settings",
                        {"max_derogation_days": body.max_derogation_days, "actor": _actor(user)})
