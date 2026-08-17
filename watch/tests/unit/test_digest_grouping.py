"""Unit tests for the CVE-aware alert grouping.

`group_alerts` folds NVD and KEV records that describe the same CVE
into a single :class:`AlertGroup`. A miss here either duplicates a
critical vulnerability across two cards (noisy) or hides the KEV flag
under the NVD row (loss of "exploited in the wild" signal).
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from digest_grouping import _extract_cve_id, group_alerts  # noqa: E402


class _Alert:
    def __init__(self, source, external_id, title="", severity="medium",
                 cvss=None, epss=None, kev=False, references=None):
        self.id = uuid.uuid4()
        self.source = source
        self.external_id = external_id
        self.title = title
        self.severity = severity
        self.cvss_score = cvss
        self.epss_score = epss
        self.kev_listed = kev
        self.references_json = references or []


class TestExtractCveId:
    def test_nvd_external_id(self):
        a = _Alert("nvd", "CVE-2025-1234")
        assert _extract_cve_id(a) == "CVE-2025-1234"

    def test_kev_external_id(self):
        a = _Alert("kev", "CVE-2024-9999")
        assert _extract_cve_id(a) == "CVE-2024-9999"

    def test_certfr_falls_back_to_title_scan(self):
        a = _Alert("certfr", "CERTFR-2025-AVI-001",
                   title="Vulnérabilité CVE-2025-5678 dans Apache")
        assert _extract_cve_id(a) == "CVE-2025-5678"

    def test_no_cve_returns_none(self):
        a = _Alert("certfr", "CERTFR-2025-AVI-001", title="Avis Apache")
        assert _extract_cve_id(a) is None

    def test_case_insensitive_match(self):
        a = _Alert("ghsa", "GHSA-xxxx", title="see cve-2025-0001")
        assert _extract_cve_id(a) == "CVE-2025-0001"


class TestGrouping:
    def test_nvd_kev_same_cve_collapsed(self):
        a1 = _Alert("nvd", "CVE-2025-1234", cvss=9.8, severity="critical")
        a2 = _Alert("kev", "CVE-2025-1234", kev=True, severity="critical")
        groups = group_alerts([a1, a2])
        assert len(groups) == 1
        g = groups[0]
        assert g.cve_id == "CVE-2025-1234"
        assert g.kev_listed is True
        assert g.max_cvss == 9.8
        assert set(g.sources) == {"nvd", "kev"}

    def test_nvd_preferred_as_primary(self):
        # NVD has CVSS vector + affected refs → it's the richer record.
        nvd = _Alert("nvd", "CVE-2025-1234", cvss=9.0)
        kev = _Alert("kev", "CVE-2025-1234", kev=True)
        groups = group_alerts([kev, nvd])  # order-independent
        assert groups[0].primary.source == "nvd"
        assert groups[0].siblings[0].source == "kev"

    def test_certfr_kept_separate(self):
        nvd = _Alert("nvd", "CVE-2025-1234", cvss=9.0)
        certfr = _Alert("certfr", "CERTFR-2025-AVI-001", title="No CVE here")
        groups = group_alerts([nvd, certfr])
        assert len(groups) == 2

    def test_sort_by_severity_then_cvss(self):
        low = _Alert("nvd", "CVE-2025-0001", severity="low", cvss=3.0)
        crit_low_cvss = _Alert("nvd", "CVE-2025-0002", severity="critical", cvss=6.0)
        crit_high_cvss = _Alert("nvd", "CVE-2025-0003", severity="critical", cvss=9.5)
        groups = group_alerts([low, crit_low_cvss, crit_high_cvss])
        ids = [g.cve_id for g in groups]
        assert ids == ["CVE-2025-0003", "CVE-2025-0002", "CVE-2025-0001"]

    def test_kev_listed_propagates_from_sibling(self):
        nvd = _Alert("nvd", "CVE-2025-1234", kev=False, cvss=8.0)
        kev = _Alert("kev", "CVE-2025-1234", kev=True)
        groups = group_alerts([nvd, kev])
        assert groups[0].kev_listed is True
        # NVD remains primary, but the group reports kev_listed=True.
        assert groups[0].primary.source == "nvd"

    def test_empty_input_returns_empty(self):
        assert group_alerts([]) == []
