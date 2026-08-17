"""Unit tests for the matcher's pure-Python core.

We test the CPE / PURL / keyword helpers and the version-range
intersection without touching the database. Each test constructs a
plain object that mimics WatchTarget / Alert attribute access.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


class _T:
    def __init__(self, kind, value, version_constraint="", scope_id=None, id=None):
        self.kind = kind
        self.value = value
        self.version_constraint = version_constraint
        self.scope_id = scope_id
        self.id = id


class _A:
    def __init__(self, affected=None, title="", summary=""):
        self.affected_json = affected or []
        self.title = title
        self.summary = summary
        self.id = "test-alert"


# ── CPE matching ────────────────────────────────────────────────

class TestCpeMatch:
    def test_exact_cpe_matches(self):
        from matcher import _match_cpe
        t = _T("cpe", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
        affected = [{"cpe": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}]
        assert _match_cpe(t, affected).startswith("cpe:2.3:a:openssl:openssl")

    def test_wildcard_alert_cpe(self):
        from matcher import _match_cpe
        t = _T("cpe", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
        affected = [{"cpe": "cpe:2.3:a:openssl:*:*:*:*:*:*:*:*:*"}]
        assert _match_cpe(t, affected)

    def test_different_vendor_no_match(self):
        from matcher import _match_cpe
        t = _T("cpe", "cpe:2.3:a:openssl:openssl:*")
        affected = [{"cpe": "cpe:2.3:a:apache:httpd:*"}]
        assert not _match_cpe(t, affected)

    def test_invalid_target_cpe(self):
        from matcher import _match_cpe
        t = _T("cpe", "openssl")  # missing cpe:2.3: prefix
        affected = [{"cpe": "cpe:2.3:a:openssl:openssl:*"}]
        assert not _match_cpe(t, affected)

    def test_empty_affected(self):
        from matcher import _match_cpe
        t = _T("cpe", "cpe:2.3:a:openssl:openssl:*")
        assert not _match_cpe(t, [])


# ── PURL matching ───────────────────────────────────────────────

class TestPurlMatch:
    def test_npm_match(self):
        from matcher import _match_purl
        t = _T("purl", "pkg:npm/lodash")
        affected = [{"purl": "pkg:npm/lodash"}]
        assert _match_purl(t, affected) == "pkg:npm/lodash"

    def test_case_insensitive(self):
        from matcher import _match_purl
        t = _T("purl", "pkg:NPM/Lodash")
        affected = [{"purl": "pkg:npm/lodash"}]
        assert _match_purl(t, affected)

    def test_different_ecosystem(self):
        from matcher import _match_purl
        t = _T("purl", "pkg:npm/lodash")
        affected = [{"purl": "pkg:pypi/lodash"}]
        assert not _match_purl(t, affected)

    def test_version_constraint_overlap(self):
        from matcher import _match_purl
        t = _T("purl", "pkg:pypi/django", version_constraint="<4.0.0")
        affected = [{"purl": "pkg:pypi/django", "version_range": ">=3.0.0,<3.2.5"}]
        assert _match_purl(t, affected)

    def test_version_constraint_disjoint(self):
        from matcher import _match_purl
        t = _T("purl", "pkg:pypi/django", version_constraint=">=5.0.0")
        affected = [{"purl": "pkg:pypi/django", "version_range": "<4.0.0"}]
        # boundary probing: target has 5.0.0 (>=), advisory has 4.0.0 (<).
        # 4.0.0 fails t_spec; 5.0.0 fails a_spec. So no probe satisfies both.
        assert not _match_purl(t, affected)

    def test_invalid_purl(self):
        from matcher import _match_purl
        t = _T("purl", "not-a-purl")
        affected = [{"purl": "pkg:npm/lodash"}]
        assert not _match_purl(t, affected)


# ── Keyword matching ────────────────────────────────────────────

class TestKeywordMatch:
    def test_title_substring(self):
        from matcher import _match_keyword
        t = _T("keyword", "OpenSSL")
        a = _A(title="OpenSSL 3.0 fixes critical buffer overflow")
        assert _match_keyword(t, a, [])

    def test_summary_substring(self):
        from matcher import _match_keyword
        t = _T("keyword", "log4j")
        a = _A(summary="A new RCE in Apache Log4J was discovered.")
        assert _match_keyword(t, a, [])

    def test_vendor_field(self):
        from matcher import _match_keyword
        t = _T("keyword", "apache")
        a = _A()
        assert _match_keyword(t, a, [{"vendor": "Apache", "product": "httpd"}])

    def test_no_match(self):
        from matcher import _match_keyword
        t = _T("keyword", "nginx")
        a = _A(title="OpenSSL fixes")
        assert not _match_keyword(t, a, [{"vendor": "openssl"}])

    def test_empty_keyword(self):
        from matcher import _match_keyword
        t = _T("keyword", "")
        a = _A(title="anything")
        assert not _match_keyword(t, a, [])


# ── Version constraint intersection ─────────────────────────────

class TestVersionIntersection:
    def test_target_open_matches_anything(self):
        from matcher import _version_constraint_intersects
        assert _version_constraint_intersects("", "<3.0.0")

    def test_advisory_open_matches_anything(self):
        from matcher import _version_constraint_intersects
        assert _version_constraint_intersects("<2.0.0", "")

    def test_overlap(self):
        from matcher import _version_constraint_intersects
        # target accepts <3.0.0, advisory affects >=2.0.0,<2.5.0
        assert _version_constraint_intersects("<3.0.0", ">=2.0.0,<2.5.0")

    def test_disjoint(self):
        from matcher import _version_constraint_intersects
        assert not _version_constraint_intersects(">=5.0.0", "<4.0.0")

    def test_invalid_specifier_falls_through(self):
        from matcher import _to_specifier
        assert _to_specifier("not-a-version") is None
