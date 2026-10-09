"""BUG-92 — a key can be cleared from Pilot's settings screen, and is.

A configured key shows as bullets. The save sent a key only when the field
held one, so a key could never be cleared: it stayed in Pilot and kept going
to every module. Focusing a field clears its bullets, as before, and a
configured key gets a "Clear the key" button: only that button clears it, a
field left empty (typed into then erased included) keeps the stored key. The
value to send is ``_aiKeyToSend(value, cleared)``. Locks, running the
compiled functions under node against a stub DOM:
  - untouched bullets, or an empty field not cleared by the button: nothing
    is sent;
  - a typed key is sent; a key cleared by the button is sent empty;
  - focus clears the bullets; typing then erasing keeps the stored key;
  - the clear button empties and marks the field, and shows for a
    configured key only;
  - the save sends every key through the same path, and trims the proxy.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parents[2] / "app"
_JS = (_APP / "js" / "Pilot_app.js").read_text(encoding="utf-8")
_BULLETS = "•" * 8

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node not installed")


def _code(pattern: str) -> str:
    m = re.search(r"^([ \t]*)" + pattern + r".*?^\1\}", _JS, re.S | re.M)
    assert m, pattern
    return m.group(0)


_STUBS = """
var elements = {};
function el(id, value) { elements[id] = {id: id, value: value, dataset: {}, placeholder: ""}; return elements[id]; }
var document = {getElementById: function(id) { return elements[id] || null; }};
var window = {};
function t(k) { return k; } function esc(s) { return String(s); } function _da(v) { return JSON.stringify(v); }
function _icon() { return ""; } function _aiModelOptions() { return ""; }
"""


def _run(body: str, *functions: str):
    script = _STUBS + "\n".join(_code(f) for f in functions) + "\n" + body
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout.strip()
    return json.loads(out)


@pytest.mark.parametrize("value,edited,sent", [
    (_BULLETS, False, None), ("", False, None), ("sk-medsecure", True, "sk-medsecure"),
    ("", True, ""), (None, True, None),
])
def test_the_value_sent_for_a_key_field(value, edited, sent):
    assert _run(f"console.log(JSON.stringify(_aiKeyToSend({json.dumps(value)}, {json.dumps(edited)})));",
                r"function _aiKeyToSend\(") == sent


def test_focus_clears_the_bullets_and_erasing_keeps_the_key():
    out = _run(f"""
var e = el("set-key-openai", {json.dumps(_BULLETS)}); _bindAiKeyFocusHandlers();
e.onfocus.call(e); var afterFocus = e.value;
e.value = "sk-new"; if (e.oninput) e.oninput.call(e); var typed = _aiKeyToSend(e.value, !!e.dataset.cleared);
e.value = ""; if (e.oninput) e.oninput.call(e);
console.log(JSON.stringify([afterFocus, typed, _aiKeyToSend(e.value, !!e.dataset.cleared)]));
""", r"function _aiKeyToSend\(", r"function _bindAiKeyFocusHandlers\(")
    assert out == ["", "sk-new", None]


def test_the_clear_button_empties_and_marks_the_field():
    out = _run(f"""
var e = el("set-key-openai", {json.dumps(_BULLETS)}); window._clearAiKey("set-key-openai");
console.log(JSON.stringify([e.value, e.dataset.cleared, _aiKeyToSend(e.value, !!e.dataset.cleared)]));
""", r"function _aiKeyToSend\(", r"window\._clearAiKey = function")
    assert out == ["", "1", ""]


@pytest.mark.parametrize("configured", [True, False])
def test_the_clear_button_shows_for_a_configured_key_only(configured):
    settings = {"ai_key_openai": "configured" if configured else ""}
    html = _run(f"console.log(JSON.stringify(_renderAiProviderFields('openai', {json.dumps(settings)})));",
                r"function _keyInput\(", r"function _renderAiProviderFields\(")
    assert ('data-click="_clearAiKey"' in html) is configured


def test_the_save_sends_every_key_through_it():
    src = (_APP / "ts" / "Pilot_app.ts").read_text(encoding="utf-8")
    body = src[src.index("window._saveSettings = function"):]
    body = body[:body.index("\n};")]
    for field, key in (("set-key-anthropic", "ai_key_anthropic"), ("set-key-openai", "ai_key_openai"),
                       ("set-key-gemini", "ai_key_gemini"), ("set-custom-key", "ai_custom_key")):
        assert f'_keyField("{field}", "{key}")' in body, field
    assert "_aiKeyToSend(el ? el.value : null, !!(el && el.dataset.cleared))" in body  # the button's mark, not typing
    for field in ("set-http-proxy", "set-https-proxy", "set-no-proxy"):
        assert f'(_val("{field}") || "").trim()' in body, field
