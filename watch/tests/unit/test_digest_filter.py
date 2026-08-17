"""Unit tests for the per-scope digest threshold filter.

`digest_filter.passes_threshold` combines four scope-configurable rules
with OR semantics: severity floor, KEV inclusion, CVSS floor, EPSS floor.
Bugs here either spam recipients with low-severity noise or silently
suppress the very alerts the scope was set up to surface.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from digest_filter import passes_threshold  # noqa: E402


class _Alert:
    def __init__(self, severity="medium", cvss=None, epss=None, kev=False):
        self.severity = severity
        self.cvss_score = cvss
        self.epss_score = epss
        self.kev_listed = kev


class _Scope:
    def __init__(self, severity_min="critical", include_kev=True,
                 cvss_min=None, epss_min=None):
        self.digest_severity_min = severity_min
        self.digest_include_kev = include_kev
        self.digest_cvss_min = cvss_min
        self.digest_epss_min = epss_min


class TestSeverityFloor:
    def test_critical_passes_critical_floor(self):
        assert passes_threshold(_Alert(severity="critical"), _Scope())

    def test_high_blocked_by_critical_floor(self):
        s = _Scope(include_kev=False)
        assert not passes_threshold(_Alert(severity="high"), s)

    def test_high_passes_high_floor(self):
        s = _Scope(severity_min="high", include_kev=False)
        assert passes_threshold(_Alert(severity="high"), s)

    def test_unknown_severity_blocked(self):
        s = _Scope(include_kev=False)
        assert not passes_threshold(_Alert(severity="unknown"), s)


class TestKevGate:
    def test_kev_low_severity_passes_when_enabled(self):
        # Low severity but KEV-listed → caller wanted the KEV signal.
        s = _Scope(severity_min="critical", include_kev=True)
        assert passes_threshold(_Alert(severity="low", kev=True), s)

    def test_kev_low_severity_blocked_when_disabled(self):
        s = _Scope(severity_min="critical", include_kev=False)
        assert not passes_threshold(_Alert(severity="low", kev=True), s)


class TestCvssFloor:
    def test_cvss_above_floor_passes(self):
        s = _Scope(severity_min="critical", include_kev=False, cvss_min=7.0)
        assert passes_threshold(_Alert(severity="medium", cvss=8.1), s)

    def test_cvss_below_floor_blocked(self):
        s = _Scope(severity_min="critical", include_kev=False, cvss_min=7.0)
        assert not passes_threshold(_Alert(severity="medium", cvss=5.5), s)

    def test_no_floor_does_not_pass(self):
        # cvss_min=None → that gate is disabled, not "auto-pass".
        s = _Scope(severity_min="critical", include_kev=False, cvss_min=None)
        assert not passes_threshold(_Alert(severity="medium", cvss=9.9), s)

    def test_cvss_none_with_floor_blocked(self):
        s = _Scope(severity_min="critical", include_kev=False, cvss_min=7.0)
        assert not passes_threshold(_Alert(severity="medium", cvss=None), s)


class TestEpssFloor:
    def test_epss_above_floor_passes(self):
        s = _Scope(severity_min="critical", include_kev=False, epss_min=0.5)
        assert passes_threshold(_Alert(severity="medium", epss=0.8), s)

    def test_epss_below_floor_blocked(self):
        s = _Scope(severity_min="critical", include_kev=False, epss_min=0.5)
        assert not passes_threshold(_Alert(severity="medium", epss=0.2), s)


class TestOrSemantics:
    def test_any_rule_match_wins(self):
        # Severity floor would block, but CVSS rule passes → overall pass.
        s = _Scope(severity_min="critical", include_kev=False, cvss_min=7.0)
        assert passes_threshold(_Alert(severity="medium", cvss=9.0), s)

    def test_all_rules_blocked_blocks_alert(self):
        s = _Scope(severity_min="critical", include_kev=False,
                   cvss_min=9.5, epss_min=0.9)
        a = _Alert(severity="medium", cvss=7.0, epss=0.4, kev=False)
        assert not passes_threshold(a, s)


class TestDigestSuppression:
    """Two vectors put historical CVEs into a "since last send" digest: the
    retro-match at target creation (backfill) and the matcher re-running when
    a source modifies an old entry. Both are digest-suppressed. The only
    exception is a KEV flip that happened inside the window — newly exploited
    is news; KEV-since-forever is backlog."""

    def _t(self, days_ago):
        from datetime import datetime, timedelta, timezone
        return datetime.now(timezone.utc) - timedelta(days=days_ago)

    def test_backfill_match_is_suppressed(self):
        from digest_filter import digest_suppressed
        assert digest_suppressed("backfill", None, self._t(0), self._t(1))

    def test_stale_rematch_is_suppressed(self):
        # CVE first ingested weeks before the window: a source modification
        # re-matched it, but it is not news.
        from digest_filter import digest_suppressed
        assert digest_suppressed("keyword", None, self._t(20), self._t(1))

    def test_fresh_ingestion_reaches_the_digest(self):
        from digest_filter import digest_suppressed
        for kind in ("keyword", "cpe", "purl"):
            assert not digest_suppressed(kind, None, self._t(0), self._t(1))

    def test_kev_flip_inside_window_reaches_the_digest(self):
        # Old CVE, old ingestion, even a backfill match — but it entered the
        # KEV catalogue since the last send: that IS the news.
        from digest_filter import digest_suppressed
        assert not digest_suppressed("keyword", self._t(0), self._t(300), self._t(1))
        assert not digest_suppressed("backfill", self._t(0), self._t(300), self._t(1))

    def test_kev_flip_before_window_is_backlog(self):
        from digest_filter import digest_suppressed
        assert digest_suppressed("keyword", self._t(30), self._t(300), self._t(1))
        assert digest_suppressed("backfill", self._t(30), self._t(300), self._t(1))

    def test_kev_since_before_tracking_is_backlog(self):
        # kev_listed_at NULL = listed before the column existed → historical.
        from digest_filter import digest_suppressed
        assert digest_suppressed("backfill", None, self._t(300), self._t(1))

    def test_missing_dates_do_not_suppress(self):
        from digest_filter import digest_suppressed
        assert not digest_suppressed("keyword", None, None, self._t(1))
