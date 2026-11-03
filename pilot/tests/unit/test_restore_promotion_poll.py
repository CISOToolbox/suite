"""The restore screen stops polling a promotion state it cannot read.

``_rstPollPromotion`` retried every 5 s, forever and silently, when the
status request failed (Pilot or the agent unreachable). It now backs off,
stops after a few failures and says so. Runs the compiled function under
node against stubbed timers and fetch.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_PILOT = (Path(__file__).resolve().parents[2] / "app" / "js" / "Pilot_app.js").read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node not installed")


def _code(pattern: str) -> str:
    m = re.search(r"^([ \t]*)" + pattern + r".*?^\1\}", _PILOT, re.S | re.M)
    assert m, pattern
    return m.group(0)


_STUBS = """
var _rstPromoTimer = null, _rstPromotion = null, _rstModule = "risk";
var _rstPromoFails = 0, _rstPromoError = "";
var _panel = "backups", _bkTab = "restore";
var timers = [], fetches = 0;
var window = {setTimeout: function(fn, ms) { timers.push([fn, ms]); return timers.length; },
              clearTimeout: function() {}};
function _fetch() { fetches++; return Promise.reject(new Error("API 502: Bad Gateway")); }
function _renderPanel() {}
function showStatus() {}
function t(k) { return k; }
"""


def test_polling_backs_off_then_stops_with_a_visible_error():
    script = _STUBS + _code(r"function _rstPollPromotion\(") + """
(async function() {
    var delays = [];
    _rstPollPromotion("risk");
    for (var i = 0; i < 20; i++) {
        await new Promise(function(r) { setImmediate(r); });
        var next = timers.shift();
        if (!next) break;
        delays.push(next[1]);
        next[0]();
    }
    console.log(JSON.stringify({fetches: fetches, delays: delays, error: _rstPromoError}));
})();
"""
    out = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True,
                                    check=True).stdout.strip())
    assert out["fetches"] < 20, "polls forever"
    assert out["delays"] == sorted(out["delays"]) and out["delays"][-1] > out["delays"][0]
    assert "502" in out["error"]
