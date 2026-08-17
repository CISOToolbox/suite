"""Unit tests for the composite risk scorer (M11).

The scorer collapses CVSS, EPSS, KEV and (eventually) PoC signals into
a single 0..100 number and a verbal urgency. These tests pin the
contribution formulas, the boost multipliers, and the urgency ladder
so a future refactor cannot silently drift the digest sort order.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from risk_scorer import score_group, _label_for, _urgency_for, _days_since  # noqa: E402


class _Alert:
    def __init__(self, published_at=None):
        self.published_at = published_at


class _Group:
    """Minimal AlertGroup duck-type — only the fields score_group reads."""
    def __init__(self, cvss=None, epss=None, kev=False, published_at=None):
        self.max_cvss = cvss
        self.max_epss = epss
        self.kev_listed = kev
        self.primary = _Alert(published_at=published_at)


# ── Component contributions ─────────────────────────────────────────


class TestContributions:
    def test_cvss_contribution_full(self):
        # CVSS 10 → 20 points
        r = score_group(_Group(cvss=10.0))
        assert r.cvss_contribution == 20.0

    def test_cvss_contribution_partial(self):
        r = score_group(_Group(cvss=5.0))
        assert r.cvss_contribution == 10.0

    def test_cvss_contribution_zero_when_missing(self):
        r = score_group(_Group())
        assert r.cvss_contribution == 0.0

    def test_epss_contribution_full(self):
        # EPSS 1.0 → 35 points
        r = score_group(_Group(epss=1.0))
        assert r.epss_contribution == 35.0

    def test_epss_contribution_partial(self):
        r = score_group(_Group(epss=0.5))
        assert abs(r.epss_contribution - 17.5) < 1e-6

    def test_kev_contribution_listed(self):
        r = score_group(_Group(kev=True))
        assert r.kev_contribution == 30.0

    def test_kev_contribution_unlisted(self):
        r = score_group(_Group(kev=False))
        assert r.kev_contribution == 0.0

    def test_poc_contribution_default_none(self):
        r = score_group(_Group())
        assert r.poc_contribution == 0.0

    def test_poc_contribution_weaponized(self):
        r = score_group(_Group(), poc_confidence="WEAPONIZED")
        assert r.poc_contribution == 15.0

    def test_poc_contribution_unknown_value_falls_back_to_none(self):
        r = score_group(_Group(), poc_confidence="not-a-real-confidence")
        assert r.poc_confidence == "NONE"
        assert r.poc_contribution == 0.0


# ── Boost multipliers ───────────────────────────────────────────────


class TestBoosters:
    def test_no_boost_by_default(self):
        r = score_group(_Group(cvss=5.0, epss=0.1))
        assert r.boosters_applied == ()

    def test_kev_plus_poc_boost(self):
        # KEV + any non-NONE PoC → ×1.15
        base = score_group(_Group(cvss=8.0, kev=True), poc_confidence="NONE")
        boosted = score_group(_Group(cvss=8.0, kev=True), poc_confidence="PUBLIC_POC_LOW_QUALITY")
        assert "KEV+PoC" in boosted.boosters_applied
        # Boosted score must include the ×1.15 multiplier on the new base.
        assert boosted.risk_score > base.risk_score

    def test_high_cvss_plus_high_epss_boost(self):
        # CVSS ≥ 9.0 AND EPSS > 0.7 → ×1.10
        r = score_group(_Group(cvss=9.5, epss=0.8))
        assert "CVSS>=9+EPSS>0.7" in r.boosters_applied

    def test_high_cvss_alone_does_not_boost(self):
        r = score_group(_Group(cvss=9.5, epss=0.3))
        assert "CVSS>=9+EPSS>0.7" not in r.boosters_applied

    def test_recent_publication_boost(self):
        recent = datetime.now(timezone.utc) - timedelta(days=2)
        r = score_group(_Group(cvss=5.0, published_at=recent))
        assert "Published<=7days" in r.boosters_applied

    def test_old_publication_no_boost(self):
        old = datetime.now(timezone.utc) - timedelta(days=60)
        r = score_group(_Group(cvss=5.0, published_at=old))
        assert "Published<=7days" not in r.boosters_applied

    def test_score_capped_at_100(self):
        # Worst case: max CVSS + max EPSS + KEV + weaponized PoC + all 3 boosts.
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        r = score_group(
            _Group(cvss=10.0, epss=1.0, kev=True, published_at=recent),
            poc_confidence="WEAPONIZED",
        )
        assert r.risk_score == 100.0


# ── Labels ──────────────────────────────────────────────────────────


class TestLabels:
    def test_label_low(self):
        assert _label_for(0.0) == "LOW"
        assert _label_for(25.0) == "LOW"

    def test_label_medium(self):
        assert _label_for(25.01) == "MEDIUM"
        assert _label_for(50.0) == "MEDIUM"

    def test_label_high(self):
        assert _label_for(50.01) == "HIGH"
        assert _label_for(75.0) == "HIGH"

    def test_label_critical(self):
        assert _label_for(75.01) == "CRITICAL"
        assert _label_for(100.0) == "CRITICAL"


# ── Urgency ladder ──────────────────────────────────────────────────


class TestUrgency:
    def test_kev_and_high_epss_patch_immediately(self):
        assert _urgency_for(in_kev=True, epss=0.8, cvss=7.0) == "PATCH_IMMEDIATELY"

    def test_kev_alone_within_24h(self):
        assert _urgency_for(in_kev=True, epss=0.1, cvss=5.0) == "PATCH_WITHIN_24H"

    def test_high_epss_alone_within_72h(self):
        assert _urgency_for(in_kev=False, epss=0.8, cvss=5.0) == "PATCH_WITHIN_72H"

    def test_critical_cvss_this_week(self):
        assert _urgency_for(in_kev=False, epss=0.1, cvss=9.5) == "PATCH_THIS_WEEK"

    def test_high_cvss_this_month(self):
        assert _urgency_for(in_kev=False, epss=0.1, cvss=7.5) == "PATCH_THIS_MONTH"

    def test_low_cvss_next_cycle(self):
        assert _urgency_for(in_kev=False, epss=0.1, cvss=4.0) == "NEXT_CYCLE"

    def test_no_signals_next_cycle(self):
        assert _urgency_for(in_kev=False, epss=0.0, cvss=0.0) == "NEXT_CYCLE"


# ── Edge cases & robustness ─────────────────────────────────────────


class TestEdgeCases:
    def test_missing_data_yields_zero_score(self):
        r = score_group(_Group())
        assert r.risk_score == 0.0
        assert r.risk_label == "LOW"
        assert r.urgency == "NEXT_CYCLE"

    def test_iso_string_published_at_parsed(self):
        recent_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        r = score_group(_Group(cvss=5.0, published_at=recent_iso))
        assert "Published<=7days" in r.boosters_applied

    def test_iso_string_with_z_trailing(self):
        dt = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = score_group(_Group(cvss=5.0, published_at=dt))
        assert "Published<=7days" in r.boosters_applied

    def test_garbage_published_at_handled(self):
        r = score_group(_Group(cvss=5.0, published_at="not-a-date"))
        assert r.days_since_published is None
        assert "Published<=7days" not in r.boosters_applied

    def test_days_since_handles_naive_datetime(self):
        naive = datetime.utcnow() - timedelta(days=3)
        d = _days_since(naive)
        assert d is not None and 2 <= d <= 4

    def test_as_dict_shape(self):
        r = score_group(_Group(cvss=7.5, epss=0.4, kev=True))
        d = r.as_dict()
        assert "risk_score" in d
        assert "risk_label" in d
        assert "urgency" in d
        assert "components" in d
        assert "boosters_applied" in d
        # Components carry the granular breakdown.
        for k in ("cvss_score", "epss_probability", "in_kev", "poc_confidence",
                  "cvss_contribution", "epss_contribution", "kev_contribution",
                  "poc_contribution"):
            assert k in d["components"]


# ── Integration with grouping ───────────────────────────────────────


class TestGroupSorting:
    """A KEV+EPSS group must sort ahead of a higher-CVSS-only group."""

    def test_kev_outranks_higher_cvss_alone(self):
        # Imported lazily to avoid a circular import on bare-test runs.
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
        from digest_grouping import group_alerts  # noqa: WPS433

        class _A:
            def __init__(self, source, ext, cvss=None, epss=None, kev=False, sev="medium"):
                import uuid as _u
                self.id = _u.uuid4()
                self.source = source
                self.external_id = ext
                self.title = ""
                self.severity = sev
                self.cvss_score = cvss
                self.epss_score = epss
                self.kev_listed = kev
                self.references_json = []
                self.published_at = None

        # Group A: medium CVSS but KEV + high EPSS → must come first.
        a_kev = _A("nvd", "CVE-2025-0001", cvss=7.0, epss=0.9, kev=True, sev="high")
        # Group B: critical CVSS, no KEV, low EPSS → second.
        b_crit = _A("nvd", "CVE-2025-0002", cvss=9.8, epss=0.05, kev=False, sev="critical")

        groups = group_alerts([b_crit, a_kev])
        assert groups[0].cve_id == "CVE-2025-0001"
        assert groups[1].cve_id == "CVE-2025-0002"
