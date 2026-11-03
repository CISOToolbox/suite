"""The restore screen offers to replace the whole module once per session.

After a successful promotion the session stays open (to compare, then
close), and the screen kept its "restore the whole module" button: a second
click, with the confirmation typed again, replaced the live database a
second time and lost every write made in between. Runs the compiled table
renderer under node with stubbed helpers.
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


def _offers_promotion(promotion) -> bool:
    script = """
var _rstModule = "risk", _rstDiffs = {}, _rstPromotion = %s;
function t(k) { return k; }
function esc(v) { return String(v); }
function _da() { return "[]"; }
function _rstFmtDT(v) { return String(v); }
function _rstSumDiff() { return 0; }
""" % json.dumps(promotion) + _code(r"function _rstObjectsTable\(") + """
var html = _rstObjectsTable({module: "risk", session: "s1", status: "ready", time: null, objects: []});
console.log(JSON.stringify(html.indexOf('data-click="_rstPromote"') >= 0));
"""
    return json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True,
                                     check=True).stdout.strip())


def test_the_whole_module_restore_is_offered_until_this_session_is_promoted():
    assert _offers_promotion(None)
    assert _offers_promotion({"state": "failed", "session": "s1"})
    assert _offers_promotion({"state": "done", "session": "s0"})      # an earlier session
    assert not _offers_promotion({"state": "done", "session": "s1"})
