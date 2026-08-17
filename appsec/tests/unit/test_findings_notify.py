"""Unit tests for the FEAT-35 pure helpers: severity floor, prefs
extraction, alert/weekly rendering (escaping included)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ.setdefault("AUTH_MODE", "none")

from src.findings_notify import (  # noqa: E402
    APPSEC_PREF_DEFAULTS,
    appsec_prefs_of,
    iso_week_key,
    render_alert_html,
    severity_passes,
)


class TestSeverityPasses:
    def test_floor_low_lets_everything_through(self):
        for s in ("low", "medium", "high", "critical"):
            assert severity_passes(s, "low")

    def test_floor_high_blocks_medium(self):
        assert not severity_passes("medium", "high")
        assert severity_passes("high", "high")
        assert severity_passes("critical", "high")

    def test_unknown_severity_only_dropped_by_explicit_floor(self):
        assert severity_passes("weird", "low")
        assert not severity_passes("weird", "medium")


class TestPrefsExtraction:
    def test_defaults_when_absent(self):
        p = appsec_prefs_of(None)
        for k, v in APPSEC_PREF_DEFAULTS.items():
            assert p[k] == v

    def test_block_overrides_and_lang_carried(self):
        p = appsec_prefs_of({"lang": "en", "module_prefs": {"appsec": {
            "alert_min_severity": "high", "weekly_day": 3}}})
        assert p["alert_min_severity"] == "high"
        assert p["weekly_day"] == 3
        assert p["lang"] == "en"
        assert p["weekly_enabled"] is True  # untouched default


class _App:
    id = "00000000-0000-0000-0000-000000000001"
    name = "Demo <App>"


class _F:
    def __init__(self, sev, title):
        self.severity = sev
        self.title = title
        self.cve_id = None
        self.type = "sast"
        self.target = "src/<main>.py"


class TestRendering:
    def test_titles_and_targets_are_escaped(self):
        html = render_alert_html(_App(), "semgrep",
                                 [_F("critical", "<script>alert(1)</script>")], "fr")
        assert "<script>alert(1)" not in html
        assert "&lt;script&gt;" in html
        assert "&lt;main&gt;" in html

    def test_lang_fallback_to_english(self):
        html = render_alert_html(_App(), "semgrep", [_F("high", "x")], "de")
        assert "discovered new findings" in html


class TestIsoWeek:
    def test_format(self):
        from datetime import date
        assert iso_week_key(date(2026, 8, 17)) == "2026-W34"
