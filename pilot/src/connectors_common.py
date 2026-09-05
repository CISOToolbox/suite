# -----------------------------------------------------------------------------
# REPLICATED from the private shared repository (shared/python/connectors_common.py).
# DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
# Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
# -----------------------------------------------------------------------------
"""Shared connector framework for CISO Toolbox backend modules.

This file is COPIED into each module's src/ directory. Do NOT edit the
per-module copies — edit the original at shared/python/connectors_common.py
and propagate (manual copy, same flow as auth_common.py).

## What this module provides

A reusable FastAPI router for any module that consumes third-party
credentials (Microsoft Graph, GitHub, Okta, AWS, …). The router exposes:

    GET  /api/connectors                  — list connectors this module supports
    GET  /api/connectors/{id}             — masked config + `configured` flag
    PUT  /api/connectors/{id}             — admin user updates a connector
                                            (403 when CONNECTORS_MANAGED_BY_PILOT)
    POST /api/connectors/{id}/test        — smoke probe
    POST /api/connectors/{id}/run         — trigger a business action
    PUT  /api/internal/connectors/{id}    — service-token push from Pilot
                                            (bypasses managed lock)

The module supplies a mapping `{connector_id: ConnectorBinding}` listing
the connectors it consumes. Each binding carries the schema (loaded from
the matching JSON file shipped under `shared/connectors/`) and two
coroutines: `test(db)` and `run(db)`.

## Credentials storage

Each field of a connector lives in `AppSettings` under the key
`connector_<connector_id>_<field_id>`. Env vars
`CONNECTOR_<CONNECTOR_ID>_<FIELD_ID>` act as a fallback when the
AppSettings entry is empty (handy for ops who prefer baking creds into
the container).

Secret fields are masked on read (returned as the placeholder
`"configured"`); when a PUT body sends that exact placeholder back, the
stored value is preserved — same trick as the existing `m365_*` config
or the `ai_key_*` endpoints.

## Managed vs standalone mode

When `CONNECTORS_MANAGED_BY_PILOT=true`, the module reports
`managed: true` in `GET /api/connectors` and refuses regular PUTs
(returns 403). Pilot reaches the module via the bypass route
`PUT /api/internal/connectors/<id>` authenticated by `X-Service-Token`.

This mirrors the AI managed pattern from CLAUDE.md §"AI integration".
"""
from __future__ import annotations

import json
import logging
import os
import secrets as _secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.database import get_db
from src.models import AppSettings, User

logger = logging.getLogger("ciso.connectors")

# ── Configuration ─────────────────────────────────────────────────
MANAGED = os.getenv("CONNECTORS_MANAGED_BY_PILOT", "").lower() in ("1", "true", "yes")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

PLACEHOLDER = "configured"  # what we echo for secret fields on GET


# ── Binding ───────────────────────────────────────────────────────


@dataclass
class ConnectorBinding:
    """Wires a connector id to its schema + test/run coroutines.

    Provide EITHER ``schema_path`` (a Path to a JSON file copied from
    ``shared/connectors/<id>.json``) OR ``schema_dict`` (an inline dict,
    handy for modules that synthesize the schema at runtime — e.g. the
    Access bridge that maps each AccessPlugin's config_schema onto the
    framework shape).

    For cardinality="one" (singleton, v1 flavor): supply `test` and `run`
    callables that take `db`. Credentials live in AppSettings under
    `connector_<id>_<field>`.

    For cardinality="many" (multi-instance): supply a `backend`
    implementing `MultiInstanceBackend`. Routes `/instances/...` delegate
    to the backend; `test`/`run` callables are unused.
    """
    schema_path: Path | None = None
    schema_dict: dict | None = None
    test: Callable[[AsyncSession], Awaitable[tuple[bool, str]]] | None = None
    run: Callable[[AsyncSession], Awaitable[dict[str, Any]]] | None = None
    backend: "MultiInstanceBackend | None" = None

    _schema_cache: dict | None = None

    def schema(self) -> dict:
        if self._schema_cache is None:
            if self.schema_dict is not None:
                self._schema_cache = self.schema_dict
            elif self.schema_path is not None:
                self._schema_cache = json.loads(self.schema_path.read_text())
            else:
                raise ValueError(
                    "ConnectorBinding needs either schema_path or schema_dict"
                )
        return self._schema_cache

    def cardinality(self) -> str:
        """`"one"` or `"many"`. Default `"one"` for backward compat with
        schemas that don't declare it (e.g. older shared/connectors/*.json)."""
        return self.schema().get("cardinality", "one")


class MultiInstanceBackend:
    """Protocol for modules that own the storage of a multi-instance
    connector (typically a plugin system writing to its own DB table).

    The framework provides the HTTP surface; this protocol describes the
    data layer the module must implement. All methods are async and
    receive a live `AsyncSession`.

    Instance metadata returned by `list` / `get` carries:
      - ``id``: stable string identifier (uuid, slug, whatever the
        module uses internally)
      - ``label``: human-friendly label set by the admin
      - ``configured``: whether all required fields have a value
      - ``project_id`` (optional): when the module scopes instances per
        project (e.g. Access), surfaces in the Pilot UI as a chip
      - any other meta the bridge wants to expose (``enabled``,
        ``last_sync_at``, ``schedule`` …). The Pilot UI is generic and
        renders whatever keys are present.

    On read, secrets MUST be masked (return ``PLACEHOLDER`` for fields
    with ``secret: true``). The framework does NOT re-mask — backends
    are responsible because they own the storage.
    """

    async def list_instances(self, db: AsyncSession) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def get_instance(
        self, instance_id: str, db: AsyncSession
    ) -> dict[str, Any] | None:
        """Return instance metadata + masked field values, or None if not found."""
        raise NotImplementedError

    async def create_instance(
        self, body: dict[str, Any], db: AsyncSession
    ) -> dict[str, Any]:
        """Create a new instance from the body. Returns the new instance
        metadata (must include the assigned `id`). Raise HTTPException
        for validation errors."""
        raise NotImplementedError

    async def update_instance(
        self, instance_id: str, body: dict[str, Any], db: AsyncSession
    ) -> None:
        """Partial update: only fields present in body are written.
        Secret fields with value PLACEHOLDER are preserved (no-op)."""
        raise NotImplementedError

    async def delete_instance(
        self, instance_id: str, db: AsyncSession
    ) -> None:
        raise NotImplementedError

    async def test_instance(
        self, instance_id: str, db: AsyncSession
    ) -> tuple[bool, str]:
        raise NotImplementedError

    async def run_instance(
        self, instance_id: str, db: AsyncSession
    ) -> dict[str, Any]:
        raise NotImplementedError


# ── Settings helpers ──────────────────────────────────────────────


def _settings_key(connector_id: str, field_id: str) -> str:
    return f"connector_{connector_id}_{field_id}"


def _env_key(connector_id: str, field_id: str) -> str:
    return f"CONNECTOR_{connector_id.upper()}_{field_id.upper()}"


async def _get_setting(key: str, db: AsyncSession) -> str:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    return s.value if s else ""


async def _set_setting(key: str, value: str, db: AsyncSession) -> None:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    if s:
        s.value = value
    else:
        db.add(AppSettings(key=key, value=value))


async def _read_field(
    connector_id: str, field_id: str, db: AsyncSession
) -> str:
    """AppSettings first, env var fallback."""
    value = await _get_setting(_settings_key(connector_id, field_id), db)
    if value:
        return value
    return os.getenv(_env_key(connector_id, field_id), "")


async def get_credentials(
    connector_id: str, schema: dict, db: AsyncSession
) -> dict[str, str] | None:
    """Return all field values for a connector. Returns None when any
    required field is missing — used by ConnectorBinding.test/run."""
    creds: dict[str, str] = {}
    missing: list[str] = []
    for field in schema["fields"]:
        value = await _read_field(connector_id, field["id"], db)
        creds[field["id"]] = value
        if field.get("required") and not value:
            missing.append(field["id"])
    if missing:
        return None
    return creds


def _mask(schema: dict, raw: dict[str, str]) -> dict[str, str]:
    """Replace secret fields with PLACEHOLDER when set."""
    out: dict[str, str] = {}
    for field in schema["fields"]:
        fid = field["id"]
        value = raw.get(fid, "")
        if field.get("secret") and value:
            out[fid] = PLACEHOLDER
        else:
            out[fid] = value
    return out


def _is_configured(schema: dict, raw: dict[str, str]) -> bool:
    fields = schema.get("fields", [])
    required = [f for f in fields if f.get("required")]
    if required:
        return all(raw.get(f["id"]) for f in required)
    # No required fields (optional-cred connectors like AWS): "configured" only
    # if at least one field actually holds a value. Otherwise the flag would be
    # a vacuous True — showing a Delete button with nothing to remove, and a
    # green "Configured" badge for a connector that is really just in demo mode.
    return any(raw.get(f["id"]) for f in fields)


# ── Auth ──────────────────────────────────────────────────────────


def _check_service_token(request: Request) -> None:
    """Internal admin-token gate, identical to routes/internal.py."""
    if not SERVICE_TOKEN:
        raise HTTPException(status_code=503, detail="Service token not configured")
    token = request.headers.get("X-Service-Token", "")
    if not token or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")


def _has_service_token(request: Request) -> bool:
    """Cheap presence-only check. Returns False if SERVICE_TOKEN is unset
    or the header is missing/empty; the actual constant-time comparison
    happens in `_check_service_token` when we commit to that auth path."""
    if not SERVICE_TOKEN:
        return False
    return bool(request.headers.get("X-Service-Token", ""))


async def _require_admin_or_service(
    request: Request, db: AsyncSession
) -> None:
    """Dual-auth gate used on read endpoints that both a browser admin
    user and a back-to-back Pilot call must reach.

    Identical pattern to the `PUT /api/ai/keys` route — first try the
    service token (constant-time compare), then fall back to user JWT
    + `require_admin`. Either path satisfies the gate."""
    if _has_service_token(request):
        _check_service_token(request)
        return
    try:
        user = await get_current_user(request, db)
    except HTTPException:
        raise HTTPException(status_code=401, detail="Not authenticated")
    require_admin(user)


# ── Router factory ────────────────────────────────────────────────


async def read_connector(
    connector_id: str, binding: ConnectorBinding, db: AsyncSession
) -> dict[str, Any]:
    """Return the same masked payload that GET /api/connectors/{id}
    produces. Public helper so Pilot's aggregator can read its own
    locally-mounted connectors without an HTTP loopback."""
    schema = binding.schema()
    raw: dict[str, str] = {}
    for field in schema["fields"]:
        raw[field["id"]] = await _read_field(connector_id, field["id"], db)
    out: dict[str, Any] = {
        "id": connector_id,
        "schema": schema,
        "managed": MANAGED,
        "configured": _is_configured(schema, raw),
    }
    out.update(_mask(schema, raw))
    return out


async def write_connector(
    connector_id: str,
    binding: ConnectorBinding,
    body: dict[str, Any],
    db: AsyncSession,
) -> None:
    """Apply a PUT body to AppSettings — same semantics as the framework's
    PUT route (partial update, secret placeholder preserved, schema
    fields only). Caller is responsible for committing."""
    await _apply_update(connector_id, binding.schema(), body, db)


async def clear_connector(
    connector_id: str, binding: ConnectorBinding, db: AsyncSession
) -> None:
    """Delete every stored field of a singleton connector from AppSettings —
    resets it to unconfigured. Removes ALL ``connector_<id>_*`` keys (including
    fields dropped from a newer schema version), not just the current schema
    fields. Env-var fallbacks (if any) still apply on the next read. Caller is
    responsible for committing."""
    prefix = _settings_key(connector_id, "")  # "connector_<id>_"
    r = await db.execute(
        select(AppSettings).where(AppSettings.key.startswith(prefix, autoescape=True))
    )
    for s in r.scalars().all():
        await db.delete(s)


def make_router(connectors: dict[str, ConnectorBinding]) -> APIRouter:
    """Return an APIRouter exposing the connector endpoints for a module.

    Usage:
        from src.connectors_common import make_router, ConnectorBinding
        from src.connectors import graph
        from src.kpi_scheduler import compute_auto_kpis_once

        app.include_router(make_router({
            "m365": ConnectorBinding(
                schema_path=Path(__file__).parent / "connector_schemas" / "m365.json",
                test=graph.test_credentials,
                run=lambda db: compute_auto_kpis_once(db),
            ),
        }))
    """
    router = APIRouter(prefix="/api", tags=["connectors"])

    def _require_binding(connector_id: str) -> ConnectorBinding:
        b = connectors.get(connector_id)
        if not b:
            raise HTTPException(status_code=404, detail="Unknown connector")
        return b

    async def _read_raw(connector_id: str, schema: dict, db: AsyncSession) -> dict[str, str]:
        out: dict[str, str] = {}
        for field in schema["fields"]:
            out[field["id"]] = await _read_field(connector_id, field["id"], db)
        return out

    def _require_singleton(binding: ConnectorBinding) -> None:
        if binding.cardinality() != "one":
            raise HTTPException(
                status_code=400,
                detail="This connector is multi-instance — use /instances/{instance_id}.",
            )

    def _require_multi(binding: ConnectorBinding) -> MultiInstanceBackend:
        if binding.cardinality() != "many":
            raise HTTPException(
                status_code=400,
                detail="This connector is singleton — use /connectors/{id}.",
            )
        if binding.backend is None:
            raise HTTPException(
                status_code=500,
                detail="Multi-instance connector missing backend implementation.",
            )
        return binding.backend

    # ---- LIST ----
    #
    # Response shape per element:
    #
    #   Singleton (cardinality=one) — field values flat at element level,
    #   alongside the meta keys (id, schema, configured). Matches the
    #   legacy m365 payload so existing UIs keep working without a config
    #   wrapper. Field IDs MUST NOT collide with the reserved keys
    #   (id, schema, configured, managed, cardinality, instances).
    #
    #   Multi-instance (cardinality=many) — no field values inline; an
    #   `instances` array is embedded, populated from the binding's
    #   MultiInstanceBackend.list_instances. Each instance has its own
    #   masked field values + meta.
    #
    # Auth: dual — admin user (browser) OR X-Service-Token (Pilot
    # aggregator). Secrets are always masked in the response.
    @router.get("/connectors")
    async def list_connectors(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        items = []
        for cid, binding in connectors.items():
            schema = binding.schema()
            item: dict[str, Any] = {
                "id": cid,
                "schema": schema,
                "cardinality": binding.cardinality(),
            }
            if binding.cardinality() == "one":
                raw = await _read_raw(cid, schema, db)
                item["configured"] = _is_configured(schema, raw)
                item.update(_mask(schema, raw))
            else:
                instances = await _safe_list_instances(binding, db)
                item["instances"] = instances
                item["configured"] = any(i.get("configured") for i in instances)
            items.append(item)
        return {"managed": MANAGED, "connectors": items}

    # ---- GET ONE ----
    @router.get("/connectors/{connector_id}")
    async def get_connector(
        connector_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        schema = binding.schema()
        out: dict[str, Any] = {
            "id": connector_id,
            "schema": schema,
            "managed": MANAGED,
            "cardinality": binding.cardinality(),
        }
        if binding.cardinality() == "one":
            raw = await _read_raw(connector_id, schema, db)
            out["configured"] = _is_configured(schema, raw)
            out.update(_mask(schema, raw))
        else:
            instances = await _safe_list_instances(binding, db)
            out["instances"] = instances
            out["configured"] = any(i.get("configured") for i in instances)
        return out

    # ── Singleton routes ─────────────────────────────────────────

    @router.put("/connectors/{connector_id}")
    async def update_connector(
        connector_id: str,
        body: dict[str, Any],
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        require_admin(user)
        if MANAGED:
            raise HTTPException(
                status_code=403,
                detail="This connector is managed by Pilot — configure it there.",
            )
        binding = _require_binding(connector_id)
        _require_singleton(binding)
        await _apply_update(connector_id, binding.schema(), body, db)
        await db.commit()
        return {"ok": True}

    @router.put("/internal/connectors/{connector_id}")
    async def push_connector(
        connector_id: str,
        body: dict[str, Any],
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        _check_service_token(request)
        binding = _require_binding(connector_id)
        _require_singleton(binding)
        await _apply_update(connector_id, binding.schema(), body, db)
        # Config pushed by Pilot (service token) — journaled, ids only,
        # never secrets (FEAT-30 P3).
        try:
            from src.audit import log_write
        except ImportError:
            from src.audit_common import log_write
        await log_write(db, None, request, "connector.push_update", actor="pilot",
                        entity_type="connector", entity_id=str(connector_id), commit=True)
        await db.commit()
        return {"ok": True}

    @router.delete("/connectors/{connector_id}")
    async def delete_connector(
        connector_id: str,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        require_admin(user)
        if MANAGED:
            raise HTTPException(
                status_code=403,
                detail="This connector is managed by Pilot — configure it there.",
            )
        binding = _require_binding(connector_id)
        _require_singleton(binding)
        await clear_connector(connector_id, binding, db)
        await db.commit()
        return {"ok": True}

    @router.delete("/internal/connectors/{connector_id}")
    async def push_delete_connector(
        connector_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        _check_service_token(request)
        binding = _require_binding(connector_id)
        _require_singleton(binding)
        await clear_connector(connector_id, binding, db)
        # Config pushed by Pilot (service token) — journaled, ids only,
        # never secrets (FEAT-30 P3).
        try:
            from src.audit import log_write
        except ImportError:
            from src.audit_common import log_write
        await log_write(db, None, request, "connector.push_delete", actor="pilot",
                        entity_type="connector", entity_id=str(connector_id), commit=True)
        await db.commit()
        return {"ok": True}

    @router.post("/connectors/{connector_id}/test")
    async def test_connector(
        connector_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        _require_singleton(binding)
        if "test" not in binding.schema().get("capabilities", []):
            raise HTTPException(status_code=400, detail="Connector does not support test")
        if binding.test is None:
            raise HTTPException(status_code=501, detail="No test handler bound")
        ok, message = await binding.test(db)
        return {"ok": ok, "message": message}

    @router.post("/connectors/{connector_id}/run")
    async def run_connector(
        connector_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        _require_singleton(binding)
        if "run" not in binding.schema().get("capabilities", []):
            raise HTTPException(status_code=400, detail="Connector does not support run")
        if binding.run is None:
            raise HTTPException(status_code=501, detail="No run handler bound")
        return await binding.run(db)

    # ── Multi-instance routes ────────────────────────────────────

    @router.get("/connectors/{connector_id}/instances")
    async def list_instances_route(
        connector_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        return {"instances": await backend.list_instances(db)}

    @router.get("/connectors/{connector_id}/instances/{instance_id}")
    async def get_instance_route(
        connector_id: str,
        instance_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        inst = await backend.get_instance(instance_id, db)
        if inst is None:
            raise HTTPException(status_code=404, detail="Unknown instance")
        return inst

    @router.post("/connectors/{connector_id}/instances")
    async def create_instance_route(
        connector_id: str,
        body: dict[str, Any],
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        require_admin(user)
        if MANAGED:
            raise HTTPException(
                status_code=403,
                detail="This connector is managed by Pilot — configure it there.",
            )
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        return await backend.create_instance(body, db)

    @router.put("/connectors/{connector_id}/instances/{instance_id}")
    async def update_instance_route(
        connector_id: str,
        instance_id: str,
        body: dict[str, Any],
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        require_admin(user)
        if MANAGED:
            raise HTTPException(
                status_code=403,
                detail="This connector is managed by Pilot — configure it there.",
            )
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        await backend.update_instance(instance_id, body, db)
        return {"ok": True}

    @router.delete("/connectors/{connector_id}/instances/{instance_id}")
    async def delete_instance_route(
        connector_id: str,
        instance_id: str,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        require_admin(user)
        if MANAGED:
            raise HTTPException(
                status_code=403,
                detail="This connector is managed by Pilot — configure it there.",
            )
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        await backend.delete_instance(instance_id, db)
        return {"ok": True}

    @router.post("/connectors/{connector_id}/instances/{instance_id}/test")
    async def test_instance_route(
        connector_id: str,
        instance_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        ok, message = await backend.test_instance(instance_id, db)
        return {"ok": ok, "message": message}

    @router.post("/connectors/{connector_id}/instances/{instance_id}/run")
    async def run_instance_route(
        connector_id: str,
        instance_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        await _require_admin_or_service(request, db)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        return await backend.run_instance(instance_id, db)

    # ── Internal push (service-token, multi-instance) ───────────

    @router.post("/internal/connectors/{connector_id}/instances")
    async def push_create_instance(
        connector_id: str,
        body: dict[str, Any],
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        _check_service_token(request)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        return await backend.create_instance(body, db)

    @router.put("/internal/connectors/{connector_id}/instances/{instance_id}")
    async def push_update_instance(
        connector_id: str,
        instance_id: str,
        body: dict[str, Any],
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        _check_service_token(request)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        await backend.update_instance(instance_id, body, db)
        # Config pushed by Pilot (service token) — journaled, ids only,
        # never secrets (FEAT-30 P3).
        try:
            from src.audit import log_write
        except ImportError:
            from src.audit_common import log_write
        await log_write(db, None, request, "connector_instance.push_update", actor="pilot",
                        entity_type="connector", entity_id=str(connector_id), commit=True)
        return {"ok": True}

    @router.delete("/internal/connectors/{connector_id}/instances/{instance_id}")
    async def push_delete_instance(
        connector_id: str,
        instance_id: str,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        _check_service_token(request)
        binding = _require_binding(connector_id)
        backend = _require_multi(binding)
        await backend.delete_instance(instance_id, db)
        # Config pushed by Pilot (service token) — journaled, ids only,
        # never secrets (FEAT-30 P3).
        try:
            from src.audit import log_write
        except ImportError:
            from src.audit_common import log_write
        await log_write(db, None, request, "connector_instance.push_delete", actor="pilot",
                        entity_type="connector", entity_id=str(connector_id), commit=True)
        return {"ok": True}

    return router


async def _safe_list_instances(
    binding: ConnectorBinding, db: AsyncSession
) -> list[dict[str, Any]]:
    """Wrap backend.list_instances — surfaces an empty list rather than a
    500 if the backend is misconfigured. Helps the Pilot UI degrade
    gracefully when one module is misbehaving."""
    if binding.backend is None:
        return []
    try:
        return await binding.backend.list_instances(db)
    except Exception as e:  # noqa: BLE001 — best-effort for list aggregation
        logger.warning("list_instances failed for %s: %s", binding, e)
        return []


# ── Update logic ──────────────────────────────────────────────────


async def _apply_update(
    connector_id: str, schema: dict, body: dict[str, Any], db: AsyncSession
) -> None:
    """Apply a PUT body to AppSettings.

    Rules:
      - only fields declared in the schema are accepted (others ignored)
      - secret fields with value == PLACEHOLDER are preserved (no-op)
      - empty string clears the value
      - missing fields are not touched (partial update)
    """
    allowed = {f["id"]: f for f in schema["fields"]}
    for field_id, field in allowed.items():
        if field_id not in body:
            continue
        value = body[field_id]
        if value is None:
            continue
        if not isinstance(value, str):
            raise HTTPException(
                status_code=400,
                detail=f"Field '{field_id}' must be a string",
            )
        # Preserve secret on placeholder echo
        if field.get("secret") and value == PLACEHOLDER:
            continue
        await _set_setting(_settings_key(connector_id, field_id), value, db)
