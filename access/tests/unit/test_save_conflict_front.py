"""Regression: the page tells a refused save from a stale-tab conflict.

The project save read any 409 as "data changed server-side": a change the
server refuses (a closed review, a review status it does not know) showed the
stale-tab alert. And saving a loaded file had no error handler at all: a
refused load failed silently. The server now marks the stale conflict
(`X-CT-Conflict: stale`); every other 409 / 422 says the server's reason, and
a failed load is surfaced.

Runs the **compiled** ``app/js/access_api.js`` (the served file), with
`fetch`, `alert`, `showStatus` and the page reload stubbed. Skipped without
``node``.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

API_JS = Path(__file__).resolve().parents[2] / "app" / "js" / "access_api.js"
HELPERS = ("_fetch", "_staleConflict", "_saveRefused", "_onSaveError", "_onLoadSaveError")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="needs node to run the shipped frontend code"
)


def _extract(source: str, name: str) -> str:
    """Return the full ``[async] function name(...) {...}`` by brace matching."""
    start = source.find("function " + name + "(")
    assert start >= 0, f"{name} is missing from access_api.js"
    if source[max(0, start - 6):start] == "async ":
        start -= 6
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
var events = [];
var BASE = "api";
var window = { location: { pathname: "/access/", reload: function() { events.push("reload"); } } };
function alert(m) { events.push("alert:" + m); }
function showStatus(m, isErr) { events.push("status:" + m); }
var console = { error: function() { events.push("console"); } };
function t(key, p) { return key + (p && p.reason !== undefined ? "|" + p.reason : ""); }
var spec = JSON.parse(process.argv[1]);
function fetch() {
    return Promise.resolve({
        status: spec.status, ok: spec.status < 400,
        headers: { get: function(h) { return (spec.headers || {})[h] || null; } },
        text: function() { return Promise.resolve(JSON.stringify({ detail: spec.detail })); },
        json: function() { return Promise.resolve({}); }
    });
}
var handler = spec.load ? _onLoadSaveError : _onSaveError;
_fetch("/projects/p", { method: "PUT", body: {} }).then(function() { events.push("ok"); }, handler)
    .then(function() { process.stdout.write(JSON.stringify(events)); });
"""


def _run(status: int, detail: str = "", headers: dict | None = None, load: bool = False) -> list[str]:
    source = API_JS.read_text(encoding="utf-8")
    script = "\n".join(_extract(source, n) for n in HELPERS) + HARNESS
    spec = {"status": status, "detail": detail, "headers": headers or {}, "load": load}
    out = subprocess.run(["node", "-e", script, "--", json.dumps(spec)],
                         capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


def test_stale_conflict_keeps_its_alert():
    assert _run(409, "stale", {"X-CT-Conflict": "stale"}) == ["alert:chrome.stale_conflict", "reload"]


@pytest.mark.parametrize("status", [409, 422])
def test_refused_change_says_the_server_reason(status):
    events = _run(status, "Review REV-1 is closed and cannot change")
    assert events == ["alert:app.save_refused|Review REV-1 is closed and cannot change", "reload"]


def test_refused_load_is_surfaced():
    events = _run(409, "A closed review cannot be deleted: REV-1", load=True)
    assert events[0] == "alert:app.save_refused|A closed review cannot be deleted: REV-1"


def test_failed_load_is_shown():
    events = _run(500, "boom", load=True)
    assert any(e.startswith("status:API 500") for e in events)
