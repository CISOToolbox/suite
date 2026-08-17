"""Unit tests for the CVE timeline + ransomware-flag computation (M13).

The metrics drive a visible badge on every digest card, so a regression
here either silently hides the "ransomware" flag or shows a nonsense
``patch_lag_days`` value to a CISO triaging the digest. Both are worse
than the chip not appearing at all — pin the behaviour.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from cve_timeline import build_timeline, _to_utc  # noqa: E402


class _Alert:
    def __init__(self, source, published_at=None, raw=None):
        self.source = source
        self.published_at = published_at
        self.raw_json = raw or {}


class _Group:
    """Minimal AlertGroup duck-type for build_timeline."""
    def __init__(self, primary, siblings=None):
        self.primary = primary
        self.siblings = siblings or []


# ── Date coercion ───────────────────────────────────────────────────


class TestToUtc:
    def test_none_returns_none(self):
        assert _to_utc(None) is None

    def test_aware_datetime_passthrough(self):
        dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
        assert _to_utc(dt) is dt

    def test_naive_datetime_assumed_utc(self):
        dt = datetime(2025, 1, 1)
        out = _to_utc(dt)
        assert out.tzinfo is timezone.utc

    def test_iso_string_with_z(self):
        out = _to_utc("2025-01-01T12:00:00Z")
        assert out.year == 2025 and out.tzinfo is not None

    def test_iso_string_with_offset(self):
        out = _to_utc("2025-01-01T12:00:00+02:00")
        assert out is not None and out.year == 2025

    def test_garbage_string_returns_none(self):
        assert _to_utc("not-a-date") is None


# ── Timeline building ───────────────────────────────────────────────


class TestTimeline:
    def test_nvd_only_no_kev_metrics(self):
        nvd = _Alert("nvd", published_at=datetime(2025, 1, 10, tzinfo=timezone.utc))
        g = _Group(primary=nvd)
        t = build_timeline(g)
        assert t.nvd_published.year == 2025
        assert t.kev_date_added is None
        assert t.patch_lag_days is None
        assert t.exploit_window_days is None
        assert t.ransomware_known is False
        assert t.ransomware_label == ""

    def test_kev_only_nvd_pub_falls_back_to_primary(self):
        # Singleton KEV (no NVD sibling) — nvd_published falls back to the primary.
        kev = _Alert("kev", published_at=datetime(2025, 2, 1, tzinfo=timezone.utc))
        g = _Group(primary=kev)
        t = build_timeline(g)
        # When primary IS KEV, nvd_published == kev date → patch_lag = 0.
        assert t.kev_date_added is not None
        assert t.patch_lag_days == 0

    def test_patch_lag_positive(self):
        nvd = _Alert("nvd", published_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
        kev = _Alert("kev", published_at=datetime(2025, 1, 11, tzinfo=timezone.utc))
        g = _Group(primary=nvd, siblings=[kev])
        t = build_timeline(g)
        assert t.patch_lag_days == 10
        assert t.exploit_window_days == 10  # fallback uses patch_lag

    def test_patch_lag_negative_floored_to_zero(self):
        # Feed inconsistency: KEV listed before NVD published (date-precision skew).
        nvd = _Alert("nvd", published_at=datetime(2025, 1, 11, tzinfo=timezone.utc))
        kev = _Alert("kev", published_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
        g = _Group(primary=nvd, siblings=[kev])
        t = build_timeline(g)
        assert t.patch_lag_days == 0

    def test_ransomware_known_flag(self):
        nvd = _Alert("nvd", published_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
        kev = _Alert(
            "kev",
            published_at=datetime(2025, 1, 5, tzinfo=timezone.utc),
            raw={"knownRansomwareCampaignUse": "Known"},
        )
        g = _Group(primary=nvd, siblings=[kev])
        t = build_timeline(g)
        assert t.ransomware_known is True
        assert t.ransomware_label == "Known"

    def test_ransomware_unknown_label(self):
        kev = _Alert(
            "kev",
            published_at=datetime(2025, 1, 5, tzinfo=timezone.utc),
            raw={"knownRansomwareCampaignUse": "Unknown"},
        )
        g = _Group(primary=kev)
        t = build_timeline(g)
        assert t.ransomware_known is False
        assert t.ransomware_label == "Unknown"

    def test_ransomware_missing_field_not_known(self):
        kev = _Alert(
            "kev",
            published_at=datetime(2025, 1, 5, tzinfo=timezone.utc),
            raw={},  # field absent
        )
        g = _Group(primary=kev)
        t = build_timeline(g)
        assert t.ransomware_known is False
        assert t.ransomware_label == ""

    def test_ransomware_case_insensitive(self):
        kev = _Alert(
            "kev",
            published_at=datetime(2025, 1, 5, tzinfo=timezone.utc),
            raw={"knownRansomwareCampaignUse": "KNOWN"},
        )
        g = _Group(primary=kev)
        t = build_timeline(g)
        assert t.ransomware_known is True

    def test_certfr_singleton_no_kev_no_nvd(self):
        # CERT-FR advisories carry no CVE id and stand alone in the group.
        cert = _Alert(
            "certfr",
            published_at=datetime(2025, 3, 1, tzinfo=timezone.utc),
        )
        g = _Group(primary=cert)
        t = build_timeline(g)
        assert t.nvd_published is not None  # falls back to primary
        assert t.kev_date_added is None
        assert t.patch_lag_days is None
        assert t.ransomware_known is False

    def test_as_dict_shape(self):
        nvd = _Alert("nvd", published_at=datetime(2025, 1, 1, tzinfo=timezone.utc))
        kev = _Alert(
            "kev",
            published_at=datetime(2025, 1, 5, tzinfo=timezone.utc),
            raw={"knownRansomwareCampaignUse": "Known"},
        )
        g = _Group(primary=nvd, siblings=[kev])
        d = build_timeline(g).as_dict()
        assert d["patch_lag_days"] == 4
        assert d["ransomware_known"] is True
        assert d["ransomware_label"] == "Known"
        assert d["nvd_published"].startswith("2025-01-01")
        assert d["kev_date_added"].startswith("2025-01-05")

    def test_string_published_at_parsed(self):
        nvd = _Alert("nvd", published_at="2025-01-01T00:00:00Z")
        kev = _Alert("kev", published_at="2025-01-08T00:00:00Z")
        g = _Group(primary=nvd, siblings=[kev])
        t = build_timeline(g)
        assert t.patch_lag_days == 7


class TestGroupIntegration:
    """End-to-end: AlertGroup.timeline and .ransomware_known propagate."""

    def test_alertgroup_exposes_timeline(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
        from digest_grouping import group_alerts

        class _A:
            def __init__(self, source, ext, published_at=None, raw=None,
                         cvss=None, sev="medium", kev=False):
                import uuid as _u
                self.id = _u.uuid4()
                self.source = source
                self.external_id = ext
                self.title = ""
                self.severity = sev
                self.cvss_score = cvss
                self.epss_score = None
                self.kev_listed = kev
                self.references_json = []
                self.affected_json = []
                self.raw_json = raw or {}
                self.published_at = published_at

        nvd = _A("nvd", "CVE-2025-7777",
                 published_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
                 cvss=9.0, sev="critical")
        kev = _A("kev", "CVE-2025-7777",
                 published_at=datetime(2025, 1, 10, tzinfo=timezone.utc),
                 raw={"knownRansomwareCampaignUse": "Known"},
                 kev=True, sev="critical")

        groups = group_alerts([nvd, kev])
        assert len(groups) == 1
        g = groups[0]
        # primary should be NVD (richer), kev is sibling
        assert g.cve_id == "CVE-2025-7777"
        assert g.timeline.patch_lag_days == 9
        assert g.ransomware_known is True
