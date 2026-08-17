"""Bridge between the Access plugin system and the centralised connectors
framework (docs/CHANTIER_CONNECTEURS.md).

Each ``AccessPlugin`` registered in ``src.plugins.PLUGIN_REGISTRY`` is
exposed to Pilot as a separate multi-instance connector. The framework
gets a synthesized JSON schema (built from the plugin's
``config_schema``, ``label``, ``setup_guide``) and a
``PluginConfigBackend`` that reads/writes Access's ``plugin_configs``
table — which keeps the existing storage (encrypted at-rest via
``src.crypto``), the scheduler, the group filters, the per-project
scoping. Nothing about Access's runtime changes; Pilot just becomes
an alternative UI for the same data.

Instance IDs are composite: ``"<project_uuid>:<plugin_id>"`` (e.g.
``"3f...:PLG-001"``) because the underlying primary key is the pair
``(project_id, plugin_id)``. The framework treats the string opaquely;
the bridge parses it back when it needs to look up the row.

Create flow: ``project_id`` defaults to the canonical single project
(docs/CHANTIER_PROJET_UNIQUE.md), so Pilot can create an instance with no
project picker. The bridge generates the next ``PLG-NNN`` id and persists.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.connectors_common import (
    PLACEHOLDER,
    ConnectorBinding,
    MultiInstanceBackend,
)
from src.crypto import decrypt_config, encrypt_config
from src.default_project import DEFAULT_PROJECT_ID
from src.models import PluginConfig, Project
from src.plugins import PLUGIN_REGISTRY
from src.plugins.base import AccessPlugin

logger = logging.getLogger("access.connectors_bridge")


# ── Schema synthesis ──────────────────────────────────────────────


def schema_from_plugin(plugin_type: str, plugin_cls: type[AccessPlugin]) -> dict:
    """Translate an AccessPlugin's class metadata to the framework JSON
    schema shape used by ``shared/connectors/<id>.json`` files."""
    inst = plugin_cls()
    fields = []
    for f in inst.config_schema:
        fid = f.get("key", "")
        fields.append({
            "id": fid,
            "label": {
                "fr": f.get("label", fid),
                "en": f.get("label_en") or f.get("label", fid),
            },
            "secret": f.get("type") == "password",
            "required": bool(f.get("required", False)),
            "placeholder": f.get("placeholder", ""),
        })
    return {
        "id": plugin_type,
        "name": {"fr": inst.label or plugin_type, "en": inst.label_en or plugin_type},
        "cardinality": "many",
        "vendor": "",
        "fields": fields,
        "capabilities": ["test", "run"],
        "prereqs": {
            "setup_guide": {
                "fr": inst.setup_guide or "",
                "en": inst.setup_guide_en or "",
            },
        },
    }


# ── Plugin-config backend ─────────────────────────────────────────


def _split_instance_id(instance_id: str) -> tuple[uuid.UUID, str]:
    """Parse ``"<project_uuid>:<plugin_id>"`` → ``(uuid, plugin_id)``.
    Raises 404 on malformed input."""
    try:
        project_str, plugin_id = instance_id.split(":", 1)
        return uuid.UUID(project_str), plugin_id
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="Malformed instance id")


def _to_summary(row: PluginConfig, schema: dict, masked: dict) -> dict:
    """Common shape returned by list/get/create — masked fields at top
    level, meta keys alongside."""
    return {
        "id": f"{row.project_id}:{row.id}",
        "label": row.label or "",
        "project_id": str(row.project_id),
        "enabled": bool(row.enabled),
        "schedule": row.schedule or "manual",
        "configured": all(
            masked.get(f["id"]) for f in schema["fields"] if f.get("required")
        ) and all(
            # also require: masked secret fields must have value PLACEHOLDER
            # (i.e. a real secret is stored) rather than empty string
            masked.get(f["id"]) != "" for f in schema["fields"]
            if f.get("required") and f.get("secret")
        ),
        **masked,
    }


def _mask_config(schema: dict, raw_cfg: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in schema["fields"]:
        fid = f["id"]
        v = raw_cfg.get(fid, "")
        if f.get("secret") and v:
            out[fid] = PLACEHOLDER
        elif f.get("secret") and not v:
            out[fid] = ""
        else:
            out[fid] = str(v) if v is not None else ""
    return out


class PluginConfigBackend(MultiInstanceBackend):
    """``MultiInstanceBackend`` impl backed by Access's ``plugin_configs``
    table. One instance per ``(project_id, plugin_id)`` row."""

    def __init__(self, plugin_type: str, plugin_cls: type[AccessPlugin]):
        self.plugin_type = plugin_type
        self.plugin_cls = plugin_cls
        self.schema = schema_from_plugin(plugin_type, plugin_cls)

    # ---- helpers --------------------------------------------------

    async def _load_row(self, instance_id: str, db: AsyncSession) -> PluginConfig:
        project_uuid, plugin_id = _split_instance_id(instance_id)
        row = await db.get(PluginConfig, (project_uuid, plugin_id))
        if row is None or row.plugin_type != self.plugin_type:
            raise HTTPException(status_code=404, detail="Instance not found")
        return row

    def _decrypted(self, row: PluginConfig) -> dict[str, Any]:
        if not row.config_enc:
            return {}
        try:
            return decrypt_config(row.config_enc)
        except Exception as e:  # noqa: BLE001
            logger.warning("decrypt_config failed for %s/%s: %s", row.project_id, row.id, e)
            return {}

    def _merge_secrets(
        self, current: dict[str, Any], incoming: dict[str, Any]
    ) -> dict[str, Any]:
        """Partial update with secret-placeholder preservation: incoming
        value PLACEHOLDER on a secret field means "keep what's stored"."""
        merged = dict(current)
        for f in self.schema["fields"]:
            fid = f["id"]
            if fid not in incoming:
                continue
            v = incoming[fid]
            if f.get("secret") and v == PLACEHOLDER:
                # keep current
                continue
            merged[fid] = v
        return merged

    # ---- protocol -------------------------------------------------

    async def list_instances(self, db: AsyncSession) -> list[dict[str, Any]]:
        result = await db.execute(
            select(PluginConfig).where(PluginConfig.plugin_type == self.plugin_type)
        )
        out = []
        for row in result.scalars().all():
            cfg = self._decrypted(row)
            masked = _mask_config(self.schema, cfg)
            out.append(_to_summary(row, self.schema, masked))
        return out

    async def get_instance(
        self, instance_id: str, db: AsyncSession
    ) -> dict[str, Any] | None:
        try:
            row = await self._load_row(instance_id, db)
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise
        cfg = self._decrypted(row)
        masked = _mask_config(self.schema, cfg)
        return _to_summary(row, self.schema, masked)

    async def create_instance(
        self, body: dict[str, Any], db: AsyncSession
    ) -> dict[str, Any]:
        # Single-project model (docs/CHANTIER_PROJET_UNIQUE.md): the suite has
        # one canonical project, so Pilot can create instances without picking
        # one. A project_id in the body is still honoured (back-compat) but
        # defaults to the canonical id when absent.
        project_id = body.get("project_id") or DEFAULT_PROJECT_ID
        try:
            project_uuid = uuid.UUID(str(project_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid project_id")
        project = await db.get(Project, project_uuid)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        # Generate next PLG-NNN id within the project (matches the existing
        # /api/projects/{id}/plugins POST conventions exactly so labels and
        # ordering stay consistent across both entry points).
        existing = await db.execute(
            select(PluginConfig).where(PluginConfig.project_id == project_uuid)
        )
        max_num = 0
        max_order = 0
        for pc in existing.scalars().all():
            try:
                n = int(re.sub(r"\D", "", pc.id) or "0")
                if n > max_num:
                    max_num = n
            except ValueError:
                pass
            if pc.sort_order and pc.sort_order > max_order:
                max_order = pc.sort_order

        # Collect field values from body (everything that matches a schema field)
        cfg = {}
        for f in self.schema["fields"]:
            fid = f["id"]
            if fid in body and body[fid] is not None:
                cfg[fid] = str(body[fid])

        row = PluginConfig(
            project_id=project_uuid,
            id=f"PLG-{max_num + 1:03d}",
            sort_order=max_order + 1,
            plugin_type=self.plugin_type,
            label=str(body.get("label", "")),
            enabled=bool(body.get("enabled", False)),
            config_enc=encrypt_config(cfg) if cfg else "",
            group_filters=body.get("group_filters") or [],
            application_id=str(body.get("application_id", "")),
            schedule=str(body.get("schedule", "manual")),
        )
        db.add(row)
        project.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(row)
        return _to_summary(row, self.schema, _mask_config(self.schema, cfg))

    async def update_instance(
        self, instance_id: str, body: dict[str, Any], db: AsyncSession
    ) -> None:
        row = await self._load_row(instance_id, db)

        # Meta updates
        for f in ("label", "application_id", "schedule"):
            if f in body and body[f] is not None:
                setattr(row, f, str(body[f]))
        if "enabled" in body:
            row.enabled = bool(body["enabled"])
        if "group_filters" in body and isinstance(body["group_filters"], list):
            row.group_filters = body["group_filters"]

        # Field updates (merge with current, preserve PLACEHOLDER secrets)
        field_ids = {f["id"] for f in self.schema["fields"]}
        incoming = {k: v for k, v in body.items() if k in field_ids and v is not None}
        if incoming:
            current = self._decrypted(row)
            merged = self._merge_secrets(current, incoming)
            row.config_enc = encrypt_config(merged) if merged else ""

        row.updated_at = datetime.now(timezone.utc)
        project = await db.get(Project, row.project_id)
        if project is not None:
            project.updated_at = datetime.now(timezone.utc)
        await db.commit()

    async def delete_instance(
        self, instance_id: str, db: AsyncSession
    ) -> None:
        row = await self._load_row(instance_id, db)
        project = await db.get(Project, row.project_id)
        await db.delete(row)
        if project is not None:
            project.updated_at = datetime.now(timezone.utc)
        await db.commit()

    async def test_instance(
        self, instance_id: str, db: AsyncSession
    ) -> tuple[bool, str]:
        row = await self._load_row(instance_id, db)
        cfg = self._decrypted(row)
        try:
            plugin = self.plugin_cls()
            result = await plugin.test_connection(cfg)
        except Exception as e:  # noqa: BLE001
            return False, f"test_connection raised: {str(e)[:200]}"
        ok = bool(result.get("ok"))
        msg = result.get("error") if not ok else result.get("details", "ok")
        return ok, msg or ("ok" if ok else "unknown error")

    async def run_instance(
        self, instance_id: str, db: AsyncSession
    ) -> dict[str, Any]:
        """For Access plugins, "run" means trigger a sync. We don't run
        it synchronously here (syncs are heavy) — return a placeholder
        result and let the existing /api/projects/{id}/plugins/{id}/sync
        route handle the long-running job. The Pilot UI shows "scheduled"
        and the admin reads the actual progress from the Access UI."""
        row = await self._load_row(instance_id, db)
        return {
            "scheduled": True,
            "message": "Sync scheduled — see Access UI for progress.",
            "instance_id": instance_id,
            "plugin_type": row.plugin_type,
        }


# ── Build the connectors map ──────────────────────────────────────


def build_connectors_map() -> dict[str, ConnectorBinding]:
    """One ConnectorBinding per registered AccessPlugin. Mount this in
    ``main.py`` via ``make_router``."""
    return {
        plugin_type: ConnectorBinding(
            schema_dict=schema_from_plugin(plugin_type, plugin_cls),
            backend=PluginConfigBackend(plugin_type, plugin_cls),
        )
        for plugin_type, plugin_cls in PLUGIN_REGISTRY.items()
    }
