"""Regression: connector credentials are masked from the schema's `secret`
flag, never guessed from the key name or the input type.

Same defect class as in Access, where a `pat` and a service-account JSON
key came back in clear: the plugin list masked on key-name substrings and
the Pilot bridge on `type == "password"`. Both paths now read `"secret": True`.
"""
import os
import sys
import uuid

os.environ.setdefault("MODULE_NAME", "asset")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest  # noqa: E402

from src import connectors_bridge as bridge  # noqa: E402
from src.connectors_common import PLACEHOLDER  # noqa: E402
from src.models import AssetPluginConfig  # noqa: E402
from src.plugins import PLUGIN_REGISTRY  # noqa: E402
from src.plugins.base import AssetPlugin, SyncResult  # noqa: E402
from src.routes import plugins as plugins_route  # noqa: E402


class _PatPlugin(AssetPlugin):
    plugin_type = "medsecure_pat_test"
    config_schema = [
        {"key": "organization", "type": "text"},
        {"key": "pat", "type": "password", "secret": True},
        {"key": "service_account_json", "type": "textarea", "secret": True},
    ]

    async def test_connection(self, config):
        return {"ok": True, "error": "", "details": ""}

    async def sync(self, config, filters):
        return SyncResult()


@pytest.fixture(autouse=True)
def _registered():
    PLUGIN_REGISTRY[_PatPlugin.plugin_type] = _PatPlugin
    yield
    PLUGIN_REGISTRY.pop(_PatPlugin.plugin_type, None)


_CFG = {"organization": "medsecure", "pat": "pat-0123", "service_account_json": '{"private_key": "x"}'}


def _row(plugin_type: str, cfg: dict, monkeypatch) -> AssetPluginConfig:
    monkeypatch.setattr(plugins_route, "decrypt_config", lambda _enc: dict(cfg))
    return AssetPluginConfig(
        project_id=uuid.uuid4(), id="PLG-001", plugin_type=plugin_type, label="MedSecure",
        enabled=True, priority=100, config_enc="enc", filters={}, schedule="manual",
    )


def test_every_password_field_is_secret():
    missing = [
        f"{ptype}.{f['key']}"
        for ptype, cls in PLUGIN_REGISTRY.items()
        for f in cls.config_schema
        if f.get("type") == "password" and not f.get("secret")
    ]
    assert missing == []


def test_plugin_list_masks_declared_secrets(monkeypatch):
    out = plugins_route._to_dict(_row(_PatPlugin.plugin_type, _CFG, monkeypatch))
    assert out["config"] == {"organization": "medsecure", "pat": "****", "service_account_json": "****"}


def test_plugin_list_unknown_connector_masks_everything(monkeypatch):
    out = plugins_route._to_dict(_row("removed_connector", {"url": "https://x"}, monkeypatch))
    assert out["config"] == {"url": "****"}


def test_bridge_masks_declared_secrets():
    schema = bridge.schema_from_plugin(_PatPlugin.plugin_type, _PatPlugin)
    masked = bridge._mask_config(schema, _CFG)
    assert masked == {"organization": "medsecure", "pat": PLACEHOLDER, "service_account_json": PLACEHOLDER}
