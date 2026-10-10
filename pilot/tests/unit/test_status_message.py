"""BUG-95 — an error in the status line reads as one, long enough to be read.

``showStatus(msg, isError)`` (shared toolbar) ignored ``isError``: a failed
save or a partial push ("push failed on: …") showed in the same grey as
"saved", and went after 3 s. Locks, running the compiled function under node
against a stub DOM:
  - an error gets the ``error`` class and stays 10 s; a message 3 s, without it;
  - a newer message is not cleared by an older one's timer;
  - Pilot's settings save and resync show a failure, or a push some module
    refused, as an error; a full success as a message.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parents[2] / "app"
_SHARED = (_APP / "js" / "cisotoolbox.js").read_text(encoding="utf-8")
_PILOT = (_APP / "js" / "Pilot_app.js").read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node not installed")


def _code(src: str, pattern: str) -> str:
    m = re.search(r"^([ \t]*)" + pattern + r".*?^\1\}", src, re.S | re.M)
    assert m, pattern
    return m.group(0)


_STUBS = """
var classes = new Set();
var status = {textContent: "", classList: {
    add: function(c) { classes.add(c); }, remove: function(c) { classes.delete(c); },
    toggle: function(c, on) { if (on === undefined ? !classes.has(c) : on) classes.add(c); else classes.delete(c); },
    contains: function(c) { return classes.has(c); }}};
var document = {getElementById: function(id) { return id === "status-msg" ? status : null; }};
var timers = [];
function setTimeout(fn, ms) { timers.push([fn, ms]); }
function state() { return [status.textContent, classes.has("error")]; }
"""


def _run(body: str):
    script = _STUBS + _code(_SHARED, r"function showStatus\(") + "\n" + body
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout.strip()
    return json.loads(out)


@pytest.mark.parametrize("is_error,delay", [(True, 10000), (False, 3000)])
def test_an_error_is_styled_and_stays_longer(is_error, delay):
    out = _run(f"""
showStatus("push failed on: risk", {json.dumps(is_error)}); var shown = state();
var ms = timers[0][1]; timers[0][0]();
console.log(JSON.stringify([shown, ms, state()]));
""")
    assert out == [["push failed on: risk", is_error], delay, ["", False]]


def test_a_newer_message_outlives_the_older_timer():
    out = _run("""
showStatus("push failed on: risk", true); showStatus("saved");
timers[0][0](); var afterOld = state(); timers[1][0]();
console.log(JSON.stringify([afterOld, state()]));
""")
    assert out == [["saved", False], ["", False]]


_HANDLER_STUBS = """
var shown = [];
function showStatus(msg, isError) { shown.push([msg, !!isError]); }
function t(k) { return k; }
var document = {getElementById: function() { return null; }};
var window = {}; var _settings = null; function _renderPanel() {}
"""

_SAVE = r"window\._saveSettings = function"
_RESYNC = r"window\._resyncModules = function"
_PARTIAL = 'Promise.resolve({push: {risk: "ok", surface: "proxy: HTTP 405"}})'
_ALL_OK = 'Promise.resolve({push: {risk: "ok", surface: "ok"}})'
_REFUSED = 'Promise.reject(new Error("400: no_proxy: \'bad entry\' is not an IP or a domain"))'


def _last_status(handler: str, answer: str):
    """Run a settings handler against a stubbed API answer; the last status
    line shown, and whether it was an error."""
    script = (_HANDLER_STUBS + "\n".join(_code(_PILOT, f) for f in (
        r"function _aiKeyToSend\(", r"function _pushFailures\(", handler))
        + f"\nfunction _fetch() {{ return {answer}; }}\n"
        + ("window._saveSettings();" if "save" in handler else "window._resyncModules();")
        + "\nsetImmediate(function() { console.log(JSON.stringify(shown[shown.length - 1])); });")
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout.strip()
    return json.loads(out)


@pytest.mark.parametrize("handler", [_SAVE, _RESYNC])
@pytest.mark.parametrize("answer,is_error", [(_PARTIAL, True), (_REFUSED, True), (_ALL_OK, False)])
def test_pilot_shows_a_failed_or_partial_save_and_resync_as_an_error(handler, answer, is_error):
    msg, error = _last_status(handler, answer)
    assert error is is_error, msg
