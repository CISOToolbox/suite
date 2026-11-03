"""Regression: the page saves against the server revision it loaded.

The blob PUT carries `expected_server_rev` (FEAT-33) and the server refuses
it when a server-side writer (Pilot, a scheduled task) bumped `server_rev`
since. The page started at 0 and only learned the revision on a focus
refresh: once a project had `server_rev > 0`, every save after a load was
refused as a stale tab, the page reloaded at 0 again, and so on at each edit.
Loading or creating the project now records its `server_rev`.

Runs the **compiled** ``app/js/access_api.js`` under node with the API
stubbed. Skipped without ``node``.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

API_JS = Path(__file__).resolve().parents[2] / "app" / "js" / "access_api.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="needs node to run the shipped frontend code"
)


def _extract(source: str, marker: str) -> str:
    """Return the code from ``marker`` to the end of its brace-matched body."""
    start = source.find(marker)
    assert start >= 0, f"{marker!r} is missing from access_api.js"
    i = source.index("{", start)
    depth = 0
    while True:
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
        i += 1
        if depth == 0:
            return source[start:i]


HARNESS = r"""
var spec = JSON.parse(process.argv[1]);
var _activeId = null, _serverRev = 0, _dataReady = false, _saveTimer = null;
var D = {};
var sent = [];
var window = {};
var localStorage = { setItem: function() {}, removeItem: function() {} };
function _setDataReady() { _dataReady = true; }
function _staleConflict() {}
function _onSaveError() {}
var project = { id: "p-1", server_rev: spec.rev, data: { metadata: { organization: "MedSecure" } } };
var AccessAPI = {
    get: function() { return Promise.resolve(project); },
    create: function() { return Promise.resolve(project); },
    update: function(id, body) { sent.push(body.expected_server_rev); return Promise.resolve({}); }
};
var _initDataAndRender = function() { window._autoSave(); };
""" + "\n%s;\n%s\n%s\n" + r"""
(spec.op === "create" ? _createNew() : _load("p-1"));
setTimeout(function() { process.stdout.write(JSON.stringify({ rev: _serverRev, sent: sent })); }, 1200);
"""


def _run(op: str, rev: int) -> dict:
    source = API_JS.read_text(encoding="utf-8")
    script = HARNESS % (_extract(source, "window._autoSave = function"),
                        _extract(source, "function _load("),
                        _extract(source, "function _createNew("))
    out = subprocess.run(["node", "-e", script, "--", json.dumps({"op": op, "rev": rev})],
                         capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


@pytest.mark.parametrize("op", ["load", "create"])
def test_save_after_load_carries_the_loaded_revision(op):
    out = _run(op, 7)
    assert out["rev"] == 7
    assert out["sent"] == [7]


def test_project_without_revision_starts_at_zero():
    assert _run("load", 0)["sent"] == [0]
