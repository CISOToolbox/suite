"""Pilot aggregator for the centralised Connectors framework.

Provides the admin view used by the Pilot "Connecteurs" menu (see
``docs/CHANTIER_CONNECTEURS.md``). Returns one card per connector TYPE
(e.g. ``m365``) listing every module that declared it consumes that
type — Pilot pushes the same credentials to every consumer, so the
type is the natural unit of administration.

## Routes

All under ``/api/admin/connectors`` so they cannot collide with the
local ``/api/connectors/{id}`` pattern from the shared framework router.

* ``GET    /api/admin/connectors``                aggregate list
* ``GET    /api/admin/connectors/{id}``           single-type detail
* ``PUT    /api/admin/connectors/{id}``           write + fan-out
* ``POST   /api/admin/connectors/{id}/test``      probe (first consumer)
* ``POST   /api/admin/connectors/{id}/run``       fan-out run

## Auth

* Inbound (browser → Pilot): admin user (JWT cookie + ``require_admin``).
* Outbound (Pilot → each module): ``X-Service-Token`` header. Never
  exposed to the browser. The shared framework's dual-auth helper lets
  modules accept this token on read endpoints.

## Secrets never leave the backend

Each module's GET masks secret fields as the placeholder ``"configured"``
(see ``shared/python/connectors_common.py:_mask``). The aggregator
forwards those masked values verbatim — neither the aggregator nor the
browser ever sees a credential in clear.

## Discovery

Pilot iterates ``ModuleRegistry`` (every suite module registered with
its internal_url) and calls each module's
``GET /api/connectors`` with the service token. Modules that don't
expose the framework yet (older builds) return 404 and are skipped
silently. Pilot also includes its own locally-mounted connectors via
``app.state.connectors`` (direct binding access, no HTTP loopback).

## Push semantics (PUT)

When the admin updates a connector type, Pilot:
1. Writes the new value to its own AppSettings (if Pilot consumes
   the type), via the shared ``write_connector`` helper.
2. Fans the body out to every other consumer via
   ``PUT /api/internal/connectors/{id}`` (service-token route).
3. Returns a per-module ok/error report so the UI can show partial
   failures.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.connectors_common import (
    ConnectorBinding,
    clear_connector,
    read_connector,
    write_connector,
)
from src.database import get_db
from src.models import ModuleRegistry, User

logger = logging.getLogger("pilot.connectors_admin")

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

router = APIRouter(prefix="/api/admin/connectors", tags=["connectors-admin"])

_HTTP_TIMEOUT = 10.0
# Modules sometimes lag (cold start). We don't want a single slow module
# to wedge the whole aggregator — each remote call is bounded.

PILOT_MODULE_ID = "pilot"


# ── Helpers ───────────────────────────────────────────────────────


def _local_connectors(request: Request) -> dict[str, ConnectorBinding]:
    """Pilot's own connector bindings, stashed on app.state by main.py."""
    return getattr(request.app.state, "connectors", {})


def _service_headers() -> dict[str, str]:
    return {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}


async def _fetch_module_connectors(
    client: httpx.AsyncClient, module: ModuleRegistry
) -> list[dict[str, Any]]:
    """Best-effort: returns the module's connector list, or [] if the
    module is unreachable / older build / 4xx."""
    if not module.internal_url:
        return []
    base = module.internal_url.rstrip("/")
    try:
        resp = await client.get(
            base + "/api/connectors",
            headers=_service_headers(),
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.RequestError as e:
        logger.info("module %s connectors unreachable: %s", module.id, e)
        return []
    if resp.status_code == 404:
        return []  # older module without the framework, normal
    if not resp.is_success:
        logger.warning(
            "module %s GET /api/connectors → HTTP %s", module.id, resp.status_code
        )
        return []
    try:
        body = resp.json()
    except ValueError:
        return []
    return body.get("connectors", []) or []


async def _push_to_module(
    client: httpx.AsyncClient,
    module: ModuleRegistry,
    connector_id: str,
    body: dict[str, Any],
) -> tuple[bool, str]:
    """Push a connector config to one module via the internal route."""
    if not module.internal_url:
        return False, "no internal_url"
    base = module.internal_url.rstrip("/")
    try:
        resp = await client.put(
            f"{base}/api/internal/connectors/{connector_id}",
            headers=_service_headers(),
            json=body,
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.RequestError as e:
        return False, f"network error: {e}"
    if resp.is_success:
        return True, "ok"
    detail = ""
    try:
        detail = (resp.json() or {}).get("detail", "")[:200]
    except ValueError:
        pass
    return False, f"HTTP {resp.status_code}{(': ' + detail) if detail else ''}"


async def _delete_from_module(
    client: httpx.AsyncClient,
    module: ModuleRegistry,
    connector_id: str,
) -> tuple[bool, str]:
    """Clear a connector config on one module via the internal delete route."""
    if not module.internal_url:
        return False, "no internal_url"
    base = module.internal_url.rstrip("/")
    try:
        resp = await client.delete(
            f"{base}/api/internal/connectors/{connector_id}",
            headers=_service_headers(),
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.RequestError as e:
        return False, f"network error: {e}"
    if resp.is_success:
        return True, "ok"
    return False, f"HTTP {resp.status_code}"


async def _call_module(
    client: httpx.AsyncClient,
    module: ModuleRegistry,
    path: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any] | str]:
    """Generic auth'd module call, returns (ok, payload-or-error-string)."""
    if not module.internal_url:
        return False, "no internal_url"
    base = module.internal_url.rstrip("/")
    try:
        resp = await client.request(
            method,
            f"{base}{path}",
            headers=_service_headers(),
            json=body,
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.RequestError as e:
        return False, f"network error: {e}"
    if resp.is_success:
        try:
            return True, resp.json()
        except ValueError:
            return True, {}
    return False, f"HTTP {resp.status_code}"


def _merge_consumer(
    types: dict[str, dict[str, Any]],
    connector: dict[str, Any],
    consumer_id: str,
) -> None:
    """Aggregate one module's connector entry into the by-type map.

    Singleton (cardinality=one): merge consumers list. First-seen entry
    wins for schema/config (Pilot is processed first so its values are
    canonical for shared singletons like m365).

    Multi-instance (cardinality=many): concatenate `instances` arrays
    from every consumer. Each instance is tagged with `_owner: <module>`
    so the Pilot UI knows where to route subsequent PUT/DELETE/test/run.
    """
    cid = connector["id"]
    if cid in types:
        entry = types[cid]
        consumers = entry.setdefault("consumers", [])
        if consumer_id not in consumers:
            consumers.append(consumer_id)
        if connector.get("cardinality") == "many":
            existing_instances = entry.setdefault("instances", [])
            for inst in connector.get("instances", []):
                tagged = dict(inst)
                tagged["_owner"] = consumer_id
                existing_instances.append(tagged)
    else:
        entry = dict(connector)
        entry["consumers"] = [consumer_id]
        if entry.get("cardinality") == "many":
            entry["instances"] = [
                {**inst, "_owner": consumer_id}
                for inst in connector.get("instances", [])
            ]
        types[cid] = entry


# ── Routes ────────────────────────────────────────────────────────


@router.get("")
async def list_aggregate(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    types: dict[str, dict[str, Any]] = {}

    # 1) Pilot's own connectors first (no HTTP, direct binding access)
    local = _local_connectors(request)
    for cid, binding in local.items():
        entry = await read_connector(cid, binding, db)
        _merge_consumer(types, entry, PILOT_MODULE_ID)

    # 2) Other modules — best-effort, parallel
    result = await db.execute(select(ModuleRegistry))
    modules = [m for m in result.scalars().all() if m.id != PILOT_MODULE_ID]
    if modules:
        async with httpx.AsyncClient() as client:
            tasks = [_fetch_module_connectors(client, m) for m in modules]
            per_module = await asyncio.gather(*tasks, return_exceptions=False)
        for module, conns in zip(modules, per_module):
            for c in conns:
                _merge_consumer(types, c, module.id)

    return {"connectors": list(types.values())}


@router.get("/{connector_id}")
async def get_one_aggregate(
    connector_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    payload = await list_aggregate(request=request, user=user, db=db)
    for c in payload["connectors"]:
        if c["id"] == connector_id:
            return c
    raise HTTPException(status_code=404, detail="Unknown connector type")


@router.put("/{connector_id}")
async def update_aggregate(
    connector_id: str,
    body: dict[str, Any],
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    report: dict[str, str] = {}

    # 1) Pilot itself, if it consumes this type
    local = _local_connectors(request)
    if connector_id in local:
        try:
            await write_connector(connector_id, local[connector_id], body, db)
            await db.commit()
            report[PILOT_MODULE_ID] = "ok"
        except HTTPException as e:
            await db.rollback()
            report[PILOT_MODULE_ID] = f"HTTP {e.status_code}: {e.detail}"
            # If Pilot's own write failed (bad payload), don't fan out.
            return {"ok": False, "report": report}

    # 2) Fan out to every other consumer module
    result = await db.execute(select(ModuleRegistry))
    modules = [m for m in result.scalars().all() if m.id != PILOT_MODULE_ID]
    if modules:
        async with httpx.AsyncClient() as client:
            # Discover which other modules actually consume this type so we
            # don't push to modules that don't care (avoids spurious 404s
            # filling up the report).
            disc = await asyncio.gather(
                *(_fetch_module_connectors(client, m) for m in modules)
            )
            consumers = [
                m for m, conns in zip(modules, disc)
                if any(c.get("id") == connector_id for c in conns)
            ]
            pushes = await asyncio.gather(
                *(_push_to_module(client, m, connector_id, body) for m in consumers)
            )
            for module, (ok, msg) in zip(consumers, pushes):
                report[module.id] = "ok" if ok else msg

    all_ok = all(v == "ok" for v in report.values())
    return {"ok": all_ok, "report": report}


@router.delete("/{connector_id}")
async def delete_aggregate(
    connector_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear a connector's stored config: Pilot's own (if it consumes the
    type) plus every other consumer module, so the connector reverts to
    'not configured'. Same fan-out shape as the PUT."""
    require_admin(user)
    report: dict[str, str] = {}

    local = _local_connectors(request)
    if connector_id in local:
        try:
            await clear_connector(connector_id, local[connector_id], db)
            await db.commit()
            report[PILOT_MODULE_ID] = "ok"
        except HTTPException as e:
            await db.rollback()
            report[PILOT_MODULE_ID] = f"HTTP {e.status_code}: {e.detail}"
            return {"ok": False, "report": report}

    result = await db.execute(select(ModuleRegistry))
    modules = [m for m in result.scalars().all() if m.id != PILOT_MODULE_ID]
    if modules:
        async with httpx.AsyncClient() as client:
            disc = await asyncio.gather(
                *(_fetch_module_connectors(client, m) for m in modules)
            )
            consumers = [
                m for m, conns in zip(modules, disc)
                if any(c.get("id") == connector_id for c in conns)
            ]
            dels = await asyncio.gather(
                *(_delete_from_module(client, m, connector_id) for m in consumers)
            )
            for module, (ok, msg) in zip(consumers, dels):
                report[module.id] = "ok" if ok else msg

    all_ok = all(v == "ok" for v in report.values())
    return {"ok": all_ok, "report": report}


@router.post("/{connector_id}/test")
async def test_aggregate(
    connector_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Call test on the first consumer (Pilot if it consumes, else the
    first remote module). Creds are identical across consumers in
    managed mode so one probe is enough."""
    require_admin(user)
    local = _local_connectors(request)
    if connector_id in local:
        binding = local[connector_id]
        ok, message = await binding.test(db)
        return {"ok": ok, "message": message, "tested_on": PILOT_MODULE_ID}

    # No local consumption — probe the first remote consumer
    result = await db.execute(select(ModuleRegistry))
    modules = [m for m in result.scalars().all() if m.id != PILOT_MODULE_ID]
    async with httpx.AsyncClient() as client:
        for m in modules:
            conns = await _fetch_module_connectors(client, m)
            # Skip modules where this connector is multi-instance — a singleton
            # test is rejected there (it is tested per-instance instead).
            if any(c.get("id") == connector_id and c.get("cardinality") != "many"
                   for c in conns):
                ok, payload = await _call_module(
                    client, m, f"/api/connectors/{connector_id}/test", "POST"
                )
                if not ok:
                    return {"ok": False, "message": payload, "tested_on": m.id}
                return {**(payload or {}), "tested_on": m.id}
    raise HTTPException(status_code=404, detail="No consumer for this connector")


@router.post("/{connector_id}/run")
async def run_aggregate(
    connector_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fan out the run trigger to every consumer. Each module returns
    its own runner payload (e.g. KPI computed/skipped counts for Pilot,
    repos_scanned for a future AppSec GitHub connector)."""
    require_admin(user)
    results: dict[str, Any] = {}

    local = _local_connectors(request)
    if connector_id in local:
        try:
            results[PILOT_MODULE_ID] = await local[connector_id].run(db)
        except Exception as e:  # noqa: BLE001 — surface the error per-module
            results[PILOT_MODULE_ID] = {"error": str(e)[:200]}

    result = await db.execute(select(ModuleRegistry))
    modules = [m for m in result.scalars().all() if m.id != PILOT_MODULE_ID]
    if modules:
        async with httpx.AsyncClient() as client:
            disc = await asyncio.gather(
                *(_fetch_module_connectors(client, m) for m in modules)
            )
            # Only fan out the singleton run to modules where this connector
            # is singleton. Where it is multi-instance (cardinality=many), a
            # global run is meaningless — the module rejects it (400) and syncs
            # are triggered per-instance instead. Skip those consumers.
            consumers = [
                m for m, conns in zip(modules, disc)
                if any(c.get("id") == connector_id and c.get("cardinality") != "many"
                       for c in conns)
            ]
            runs = await asyncio.gather(
                *(_call_module(client, m, f"/api/connectors/{connector_id}/run", "POST")
                  for m in consumers)
            )
            for module, (ok, payload) in zip(consumers, runs):
                results[module.id] = payload if ok else {"error": payload}

    return {"results": results}


# ── Multi-instance routes ─────────────────────────────────────────
#
# Pattern: /api/admin/connectors/{type}/instances/{module}/{instance_id}
# The {module} segment identifies the owning module so Pilot routes the
# action to the right backend (a given instance_id is only meaningful in
# the context of one module). The module identifier matches ModuleRegistry.id
# or PILOT_MODULE_ID for Pilot itself.


async def _resolve_module(
    module_id: str, db: AsyncSession
) -> ModuleRegistry | None:
    if module_id == PILOT_MODULE_ID:
        return None  # caller branches on this
    result = await db.execute(
        select(ModuleRegistry).where(ModuleRegistry.id == module_id)
    )
    m = result.scalar_one_or_none()
    if m is None:
        raise HTTPException(status_code=404, detail=f"Unknown module: {module_id}")
    return m


@router.post("/{connector_id}/instances")
async def create_instance_aggregate(
    connector_id: str,
    body: dict[str, Any],
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new instance on a specific module.

    The body must include `module` to identify the target (e.g. `"access"`),
    plus the connector-type-specific fields. `project_id` is no longer needed:
    modules default to their single canonical project
    (docs/CHANTIER_PROJET_UNIQUE.md)."""
    require_admin(user)
    target_module = body.pop("module", None) or body.pop("_owner", None)
    if not target_module:
        raise HTTPException(
            status_code=400,
            detail="'module' field required in body (target module id)",
        )

    if target_module == PILOT_MODULE_ID:
        local = _local_connectors(request)
        binding = local.get(connector_id)
        if not binding or binding.backend is None:
            raise HTTPException(status_code=400, detail="Pilot doesn't host this multi-instance connector")
        return await binding.backend.create_instance(body, db)

    module = await _resolve_module(target_module, db)
    if module is None:
        raise HTTPException(status_code=404, detail="Module not found")
    async with httpx.AsyncClient() as client:
        ok, payload = await _call_module(
            client, module,
            f"/api/internal/connectors/{connector_id}/instances",
            "POST",
            body,
        )
    if not ok:
        raise HTTPException(status_code=502, detail=str(payload))
    return payload


@router.get("/{connector_id}/instances/{module_id}/{instance_id}")
async def get_instance_aggregate(
    connector_id: str,
    module_id: str,
    instance_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if module_id == PILOT_MODULE_ID:
        binding = _local_connectors(request).get(connector_id)
        if not binding or binding.backend is None:
            raise HTTPException(status_code=404, detail="Not found")
        inst = await binding.backend.get_instance(instance_id, db)
        if inst is None:
            raise HTTPException(status_code=404, detail="Instance not found")
        return {**inst, "_owner": PILOT_MODULE_ID}

    module = await _resolve_module(module_id, db)
    async with httpx.AsyncClient() as client:
        ok, payload = await _call_module(
            client, module,
            f"/api/connectors/{connector_id}/instances/{instance_id}",
            "GET",
        )
    if not ok:
        raise HTTPException(status_code=404, detail=str(payload))
    return {**payload, "_owner": module_id}


@router.put("/{connector_id}/instances/{module_id}/{instance_id}")
async def update_instance_aggregate(
    connector_id: str,
    module_id: str,
    instance_id: str,
    body: dict[str, Any],
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if module_id == PILOT_MODULE_ID:
        binding = _local_connectors(request).get(connector_id)
        if not binding or binding.backend is None:
            raise HTTPException(status_code=404, detail="Not found")
        await binding.backend.update_instance(instance_id, body, db)
        return {"ok": True}

    module = await _resolve_module(module_id, db)
    async with httpx.AsyncClient() as client:
        ok, payload = await _call_module(
            client, module,
            f"/api/internal/connectors/{connector_id}/instances/{instance_id}",
            "PUT",
            body,
        )
    if not ok:
        raise HTTPException(status_code=502, detail=str(payload))
    return {"ok": True}


@router.delete("/{connector_id}/instances/{module_id}/{instance_id}")
async def delete_instance_aggregate(
    connector_id: str,
    module_id: str,
    instance_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if module_id == PILOT_MODULE_ID:
        binding = _local_connectors(request).get(connector_id)
        if not binding or binding.backend is None:
            raise HTTPException(status_code=404, detail="Not found")
        await binding.backend.delete_instance(instance_id, db)
        return {"ok": True}

    module = await _resolve_module(module_id, db)
    async with httpx.AsyncClient() as client:
        ok, payload = await _call_module(
            client, module,
            f"/api/internal/connectors/{connector_id}/instances/{instance_id}",
            "DELETE",
        )
    if not ok:
        raise HTTPException(status_code=502, detail=str(payload))
    return {"ok": True}


@router.post("/{connector_id}/instances/{module_id}/{instance_id}/test")
async def test_instance_aggregate(
    connector_id: str,
    module_id: str,
    instance_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if module_id == PILOT_MODULE_ID:
        binding = _local_connectors(request).get(connector_id)
        if not binding or binding.backend is None:
            raise HTTPException(status_code=404, detail="Not found")
        ok, message = await binding.backend.test_instance(instance_id, db)
        return {"ok": ok, "message": message, "tested_on": PILOT_MODULE_ID}

    module = await _resolve_module(module_id, db)
    async with httpx.AsyncClient() as client:
        ok, payload = await _call_module(
            client, module,
            f"/api/connectors/{connector_id}/instances/{instance_id}/test",
            "POST",
        )
    if not ok:
        return {"ok": False, "message": str(payload), "tested_on": module_id}
    return {**(payload if isinstance(payload, dict) else {}), "tested_on": module_id}


@router.post("/{connector_id}/instances/{module_id}/{instance_id}/run")
async def run_instance_aggregate(
    connector_id: str,
    module_id: str,
    instance_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if module_id == PILOT_MODULE_ID:
        binding = _local_connectors(request).get(connector_id)
        if not binding or binding.backend is None:
            raise HTTPException(status_code=404, detail="Not found")
        return await binding.backend.run_instance(instance_id, db)

    module = await _resolve_module(module_id, db)
    async with httpx.AsyncClient() as client:
        ok, payload = await _call_module(
            client, module,
            f"/api/connectors/{connector_id}/instances/{instance_id}/run",
            "POST",
        )
    if not ok:
        raise HTTPException(status_code=502, detail=str(payload))
    return payload if isinstance(payload, dict) else {}
