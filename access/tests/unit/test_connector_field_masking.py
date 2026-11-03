"""Regression: connector credentials must be masked on every read.

Masking used to guess from the key name (`secret`, `password`, `key`,
`token`, `credential`) in the plugin list, and from `type == "password"` in
the Pilot bridge. The Azure DevOps `pat` matched neither, and the Google
Workspace `service_account_json` (a textarea holding an RSA private key) was
missed by the bridge: both came back in clear from `GET .../plugins` and
`GET /api/connectors`. Each credential field now declares `"secret": True`
and both read paths use that flag only.
"""
import os
import sys
import uuid

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, ROOT)

import pytest  # noqa: E402

import src.plugins as plugins  # noqa: E402
from src import connectors_bridge as bridge  # noqa: E402
from src.connectors_common import PLACEHOLDER  # noqa: E402
from src.models import PluginConfig  # noqa: E402
from src.routes import plugins as plugins_route  # noqa: E402

_PAT = "azdo-pat-0123456789abcdef"
_SA_JSON = '{"type": "service_account", "private_key": "medsecure-sa-key-material"}'


@pytest.fixture(scope="module", autouse=True)
def _load_generic_connectors():
    os.environ["ACCESS_ADDON_PATHS"] = os.path.join(ROOT, "addons", "generic")
    plugins._load_addon_connectors()
    yield
    os.environ.pop("ACCESS_ADDON_PATHS", None)


def _row(plugin_type: str, cfg: dict, monkeypatch) -> PluginConfig:
    monkeypatch.setattr(plugins_route, "decrypt_config", lambda _enc: dict(cfg))
    return PluginConfig(
        project_id=uuid.uuid4(), id="PLG-001", plugin_type=plugin_type,
        label="MedSecure", enabled=True, config_enc="enc", group_filters=[],
        application_id="", schedule="manual",
    )


class TestSchemaDeclaresSecrets:
    def test_every_password_field_is_secret(self):
        missing = [
            f"{ptype}.{f['key']}"
            for ptype, cls in plugins.PLUGIN_REGISTRY.items()
            for f in cls.config_schema
            if f.get("type") == "password" and not f.get("secret")
        ]
        assert missing == []

    @pytest.mark.parametrize("ptype,key", [
        ("azure_devops", "pat"),
        ("google_workspace", "service_account_json"),
    ])
    def test_named_credentials_are_secret(self, ptype, key):
        cls = plugins.PLUGIN_REGISTRY[ptype]
        field = next(f for f in cls.config_schema if f["key"] == key)
        assert field.get("secret") is True


class TestPluginListMasking:
    def test_azure_devops_pat_masked(self, monkeypatch):
        out = plugins_route._to_dict(
            _row("azure_devops", {"organization": "medsecure", "pat": _PAT}, monkeypatch))
        assert out["config"]["pat"] == "****"
        assert out["config"]["organization"] == "medsecure"

    def test_google_service_account_masked(self, monkeypatch):
        out = plugins_route._to_dict(_row("google_workspace", {
            "service_account_json": _SA_JSON, "admin_email": "admin@medsecure.example",
            "domain": "medsecure.example",
        }, monkeypatch))
        assert out["config"]["service_account_json"] == "****"
        assert out["config"]["admin_email"] == "admin@medsecure.example"

    def test_unknown_connector_masks_everything(self, monkeypatch):
        out = plugins_route._to_dict(
            _row("removed_connector", {"url": "https://x", "creds": "s3cr3t"}, monkeypatch))
        assert out["config"] == {"url": "****", "creds": "****"}


class TestPilotBridgeMasking:
    @pytest.mark.parametrize("ptype,cfg,key,secret_value", [
        ("azure_devops", {"organization": "medsecure", "pat": _PAT}, "pat", _PAT),
        ("google_workspace", {"service_account_json": _SA_JSON, "admin_email": "a@m.example",
                              "domain": "m.example"}, "service_account_json", _SA_JSON),
    ])
    def test_bridge_masks_secret(self, ptype, cfg, key, secret_value):
        schema = bridge.schema_from_plugin(ptype, plugins.PLUGIN_REGISTRY[ptype])
        masked = bridge._mask_config(schema, cfg)
        assert masked[key] == PLACEHOLDER
        assert secret_value not in masked.values()

    def test_placeholder_keeps_stored_service_account(self):
        backend = bridge.PluginConfigBackend(
            "google_workspace", plugins.PLUGIN_REGISTRY["google_workspace"])
        merged = backend._merge_secrets(
            {"service_account_json": _SA_JSON, "domain": "old.example"},
            {"service_account_json": PLACEHOLDER, "domain": "medsecure.example"},
        )
        assert merged == {"service_account_json": _SA_JSON, "domain": "medsecure.example"}


class TestTestConfigKeepsMaskedSecrets:
    """The edit form sends the masked secrets back as "****": testing the
    connection from it must use the stored values, as saving does."""

    def _run(self, monkeypatch, form: dict, stored: dict, send_id=True, ptype="azure_devops",
             stored_type=None):
        import asyncio
        seen: dict = {}
        cls = plugins.PLUGIN_REGISTRY[ptype]

        async def _test_connection(self, config):
            seen.update(config)
            return {"ok": True, "error": "", "details": ""}

        async def _project(*a, **k):
            return None

        monkeypatch.setattr(cls, "test_connection", _test_connection)
        monkeypatch.setattr(plugins_route, "get_project_or_404", _project)
        row = _row(stored_type or ptype, stored, monkeypatch)

        class _DB:
            async def get(self, _model, key):
                return row if key[1] == row.id else None

        class _Request:
            async def json(self):
                body = {"plugin_type": ptype, "config": form}
                if send_id:
                    body["plugin_id"] = row.id
                return body

        asyncio.run(plugins_route.test_plugin_config(row.project_id, _Request(), user=None, db=_DB()))
        return seen

    def test_masked_secret_uses_stored_value(self, monkeypatch):
        seen = self._run(monkeypatch, {"organization": "medsecure", "pat": "****"},
                         {"organization": "medsecure", "pat": _PAT})
        assert seen["pat"] == _PAT

    def test_new_secret_is_tested_as_typed(self, monkeypatch):
        seen = self._run(monkeypatch, {"organization": "medsecure", "pat": "new-pat"},
                         {"organization": "medsecure", "pat": _PAT})
        assert seen["pat"] == "new-pat"

    def test_non_secret_field_is_never_filled_from_storage(self, monkeypatch):
        seen = self._run(monkeypatch, {"organization": "****", "pat": "****"},
                         {"organization": "medsecure", "pat": _PAT})
        assert seen["organization"] == "****"

    def test_stored_secret_of_another_connector_type_is_not_used(self, monkeypatch):
        # A plugin_id naming a connector of another type must not lend its
        # stored secret (here a GitHub token under the same "access_token" key).
        seen = self._run(monkeypatch, {"organization": "medsecure", "access_token": "****"},
                         {"base_url": "https://gitlab.medsecure.example", "access_token": "glpat-stored"},
                         ptype="github", stored_type="gitlab")
        assert seen["access_token"] == "****"

    def test_new_connector_form_is_tested_as_typed(self, monkeypatch):
        seen = self._run(monkeypatch, {"organization": "medsecure", "pat": "****"},
                         {"organization": "medsecure", "pat": _PAT}, send_id=False)
        assert seen["pat"] == "****"
