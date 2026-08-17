"""Unit tests for the client add-on connector loader (src/plugins).

Locks the contract that lets a deployment drop a bespoke connector into
an add-on directory without editing core files:
- a *.py defining an AccessPlugin subclass is auto-registered by plugin_type
- test_*.py / _*.py / conftest.py are ignored
- a broken add-on (bad import) is skipped, never crashes boot
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import src.plugins as plugins  # noqa: E402

_GOOD = '''
from src.plugins.base import AccessPlugin, SyncResult


class AcmeAddonPlugin(AccessPlugin):
    plugin_type = "acme_addon_test"
    label = "Acme add-on"
    accepts_file = True

    async def test_connection(self, config):
        return {"ok": True, "error": "", "details": ""}

    async def sync(self, config, group_filters):
        return SyncResult(users=[], errors=[])
'''

_BROKEN = "import a_module_that_does_not_exist_xyz  # noqa\n"


def _write(d, name, content):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(content)
    return p


class TestAddonLoader:
    def teardown_method(self):
        plugins.PLUGIN_REGISTRY.pop("acme_addon_test", None)
        os.environ.pop("ACCESS_ADDON_PATHS", None)

    def test_loads_good_addon(self, tmp_path):
        _write(str(tmp_path), "acme.py", _GOOD)
        os.environ["ACCESS_ADDON_PATHS"] = str(tmp_path)
        plugins._load_addon_connectors()
        assert "acme_addon_test" in plugins.PLUGIN_REGISTRY
        assert plugins.PLUGIN_REGISTRY["acme_addon_test"].accepts_file is True

    def test_ignores_tests_and_private(self, tmp_path):
        _write(str(tmp_path), "test_acme.py", _GOOD)
        _write(str(tmp_path), "_acme.py", _GOOD)
        _write(str(tmp_path), "conftest.py", _GOOD)
        os.environ["ACCESS_ADDON_PATHS"] = str(tmp_path)
        plugins._load_addon_connectors()
        assert "acme_addon_test" not in plugins.PLUGIN_REGISTRY

    def test_broken_addon_is_skipped(self, tmp_path):
        _write(str(tmp_path), "broken.py", _BROKEN)
        _write(str(tmp_path), "acme.py", _GOOD)
        os.environ["ACCESS_ADDON_PATHS"] = str(tmp_path)
        # Must not raise despite the broken file; the good one still loads.
        plugins._load_addon_connectors()
        assert "acme_addon_test" in plugins.PLUGIN_REGISTRY

    def test_missing_dir_is_noop(self):
        os.environ["ACCESS_ADDON_PATHS"] = "/nonexistent/path/xyz"
        plugins._load_addon_connectors()  # no raise
        assert "acme_addon_test" not in plugins.PLUGIN_REGISTRY
