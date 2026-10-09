"""BUG-92 — saving the settings says which modules the push failed on.

``PUT /settings`` returns the push report (``push``) next to the key
validation. The save handler read only the validation and always showed
"Settings saved and pushed to modules": a module refusing the proxy, or a key
Pilot could not decrypt and therefore did not send, stayed invisible unless
someone pressed "Resync modules". Locks, on the TypeScript source: both the
save handler and the resync read the report through one helper, and the
message exists in English and French.
"""
import re
from pathlib import Path

_APP = Path(__file__).resolve().parents[2] / "app" / "ts"
_SRC = (_APP / "Pilot_app.ts").read_text(encoding="utf-8")


def _handler(name: str) -> str:
    m = re.search(r"^(?:window|\(window as any\))\." + name + r" = function\(\) \{\n(.*?)^\};",
                  _SRC, re.S | re.M)
    assert m, name
    return m.group(1)


def test_saving_reports_the_modules_the_push_failed_on():
    body = _handler("_saveSettings")
    assert "_pushFailures(resp.push" in body
    assert "pilot.settings.saved_push_partial" in body


def test_resync_reads_the_report_the_same_way():
    assert "_pushFailures(resp.push" in _handler("_resyncModules")


def test_the_message_exists_in_both_languages():
    for lang in ("en", "fr"):
        assert '"pilot.settings.saved_push_partial"' in (_APP / f"Pilot_i18n_{lang}.ts").read_text(encoding="utf-8")
