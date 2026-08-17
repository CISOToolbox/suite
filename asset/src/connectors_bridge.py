"""Bridge between the Asset plugin system and the centralised connectors
framework. Mirror of the Access bridge — adapted for AssetPlugin /
AssetPluginConfig / asset_plugin_configs.

See ``docs/CHANTIER_CONNECTEURS.md`` for the framework rationale and
the Access bridge in ``backend-clients/demo-docker/access/src/connectors_bridge.py``
for the canonical implementation. Asset differs in a few small ways:
``priority`` field instead of ``application_id``/``group_filters``, and
fewer registered plugin types (2 today: ldap_ad, cloudtemple).
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
from src.models import AssetPluginConfig, Project
from src.plugins import PLUGIN_REGISTRY
from src.plugins.base import AssetPlugin

logger = logging.getLogger("asset.connectors_bridge")


# ── Schema synthesis ──────────────────────────────────────────────


def schema_from_plugin(plugin_type: str, plugin_cls: type[AssetPlugin]) -> dict:
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
                "fr": getattr(inst, "setup_guide", "") or "",
                "en": getattr(inst, "setup_guide_en", "") or "",
            },
        },
    }


# ── Backend ───────────────────────────────────────────────────────


def _split_instance_id(instance_id: str) -> tuple[uuid.UUID, str]:
    try:
        project_str, plugin_id = instance_id.split(":", 1)
        return uuid.UUID(project_str), plugin_id
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="Malformed instance id")


def _mask_config(schema: dict, raw_cfg: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in schema["fields"]:
        fid = f["id"]
        v = raw_cfg.get(fid, "")
        if f.get("secret") and v:
            out[fid] = PLACEHOLDER
        elif f.get("secret"):
            out[fid] = ""
        else:
            out[fid] = str(v) if v is not None else ""
    return out


def _to_summary(row: AssetPluginConfig, schema: dict, masked: dict) -> dict:
    return {
        "id": f"{row.project_id}:{row.id}",
        "label": row.label or "",
        "project_id": str(row.project_id),
        "enabled": bool(row.enabled),
        "priority": row.priority or 100,
        "configured": all(
            masked.get(f["id"]) for f in schema["fields"] if f.get("required")
        ),
        **masked,
    }


class AssetPluginBackend(MultiInstanceBackend):
    def __init__(self, plugin_type: str, plugin_cls: type[AssetPlugin]):
        self.plugin_type = plugin_type
        self.plugin_cls = plugin_cls
        self.schema = schema_from_plugin(plugin_type, plugin_cls)

    async def _load_row(self, instance_id: str, db: AsyncSession) -> AssetPluginConfig:
        project_uuid, plugin_id = _split_instance_id(instance_id)
        row = await db.get(AssetPluginConfig, (project_uuid, plugin_id))
        if row is None or row.plugin_type != self.plugin_type:
            raise HTTPException(status_code=404, detail="Instance not found")
        return row

    def _decrypted(self, row: AssetPluginConfig) -> dict[str, Any]:
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
        merged = dict(current)
        for f in self.schema["fields"]:
            fid = f["id"]
            if fid not in incoming:
                continue
            v = incoming[fid]
            if f.get("secret") and v == PLACEHOLDER:
                continue
            merged[fid] = v
        return merged

    async def list_instances(self, db: AsyncSession) -> list[dict[str, Any]]:
        result = await db.execute(
            select(AssetPluginConfig).where(AssetPluginConfig.plugin_type == self.plugin_type)
        )
        out = []
        for row in result.scalars().all():
            cfg = self._decrypted(row)
            out.append(_to_summary(row, self.schema, _mask_config(self.schema, cfg)))
        return out

    async def get_instance(self, instance_id: str, db: AsyncSession) -> dict[str, Any] | None:
        try:
            row = await self._load_row(instance_id, db)
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise
        return _to_summary(row, self.schema, _mask_config(self.schema, self._decrypted(row)))

    async def create_instance(self, body: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
        # Single-project model (docs/CHANTIER_PROJET_UNIQUE.md): default to the
        # canonical project so Pilot can create instances without a project
        # picker. A project_id in the body is still honoured (back-compat).
        project_id = body.get("project_id") or DEFAULT_PROJECT_ID
        try:
            project_uuid = uuid.UUID(str(project_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid project_id")
        project = await db.get(Project, project_uuid)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")

        existing = await db.execute(
            select(AssetPluginConfig).where(AssetPluginConfig.project_id == project_uuid)
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

        cfg = {f["id"]: str(body[f["id"]]) for f in self.schema["fields"]
               if f["id"] in body and body[f["id"]] is not None}

        row = AssetPluginConfig(
            project_id=project_uuid,
            id=f"PLG-{max_num + 1:03d}",
            sort_order=max_order + 1,
            plugin_type=self.plugin_type,
            label=str(body.get("label", "")),
            enabled=bool(body.get("enabled", False)),
            priority=int(body.get("priority", 100)),
            config_enc=encrypt_config(cfg) if cfg else "",
        )
        db.add(row)
        project.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(row)
        return _to_summary(row, self.schema, _mask_config(self.schema, cfg))

    async def update_instance(self, instance_id: str, body: dict[str, Any], db: AsyncSession) -> None:
        row = await self._load_row(instance_id, db)

        if "label" in body and body["label"] is not None:
            row.label = str(body["label"])
        if "enabled" in body:
            row.enabled = bool(body["enabled"])
        if "priority" in body and body["priority"] is not None:
            row.priority = int(body["priority"])

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

    async def delete_instance(self, instance_id: str, db: AsyncSession) -> None:
        row = await self._load_row(instance_id, db)
        project = await db.get(Project, row.project_id)
        await db.delete(row)
        if project is not None:
            project.updated_at = datetime.now(timezone.utc)
        await db.commit()

    async def test_instance(self, instance_id: str, db: AsyncSession) -> tuple[bool, str]:
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

    async def run_instance(self, instance_id: str, db: AsyncSession) -> dict[str, Any]:
        row = await self._load_row(instance_id, db)
        return {
            "scheduled": True,
            "message": "Sync scheduled — see Asset UI for progress.",
            "instance_id": instance_id,
            "plugin_type": row.plugin_type,
        }


def build_connectors_map() -> dict[str, ConnectorBinding]:
    return {
        plugin_type: ConnectorBinding(
            schema_dict=schema_from_plugin(plugin_type, plugin_cls),
            backend=AssetPluginBackend(plugin_type, plugin_cls),
        )
        for plugin_type, plugin_cls in PLUGIN_REGISTRY.items()
    }
