"""Unit tests for the SMB add-on scanner's pure logic (no live SMB needed):
share-path parsing, secret masking, the built-in ruleset + custom regex,
and plain-text extraction.
"""
import os
import re
import sys

import pytest

_ADDON = os.path.join(os.path.dirname(__file__), "..", "..", "addons", "generic", "smb_scan")
sys.path.insert(0, _ADDON)

import smb_scan  # noqa: E402


class TestParseShare:
    def test_unc(self):
        assert smb_scan._parse_share(r"\\srv\share\sub") == ("srv", r"\\srv\share\sub")

    def test_forward_slash(self):
        assert smb_scan._parse_share("//srv/share") == ("srv", r"\\srv\share")

    def test_smb_scheme(self):
        assert smb_scan._parse_share("smb://srv/share/dir") == ("srv", r"\\srv\share\dir")

    def test_invalid(self):
        with pytest.raises(ValueError):
            smb_scan._parse_share(r"\\srv")


class TestMask:
    def test_long_masked(self):
        m = smb_scan._mask("AKIAIOSFODNN7EXAMPLE")
        assert "AKIA" in m and "EXAMPLE" not in m and "chars" in m

    def test_short(self):
        assert "***" in smb_scan._mask("abc")


class TestRuleset:
    def _names(self, text, custom=None):
        return {name for name, _sev, _m in smb_scan._scan_text(text, custom or [])}

    def test_private_key(self):
        assert "private_key" in self._names("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")

    def test_aws_key(self):
        assert "aws_access_key" in self._names("key = AKIAIOSFODNN7EXAMPLE end")

    def test_password_assignment(self):
        assert "password_assignment" in self._names("db_password = S3cr3tValue")

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij1234567890"
        assert "jwt" in self._names(jwt)

    def test_custom_regex(self):
        hits = smb_scan._scan_text("ref CONFIDENTIAL-12345 here", [re.compile(r"CONFIDENTIAL-\d+")])
        assert any(n == "custom_regex" for n, _s, _m in hits)

    def test_clean_text_no_hits(self):
        assert self._names("just a normal sentence with nothing secret") == set()

    def test_match_is_masked(self):
        hits = smb_scan._scan_text("password = supersecret123", [])
        assert all("supersecret123" not in masked for _n, _s, masked in hits)

    def test_per_file_cap(self):
        text = "\n".join("password = secret%d" % i for i in range(100))
        assert len(smb_scan._scan_text(text, [])) <= smb_scan._MAX_FINDINGS_PER_FILE


class TestExtractPlainText:
    def test_txt(self):
        assert "hello secret" in smb_scan._extract_text("txt", b"hello secret")

    def test_unknown_ext_decodes(self):
        assert "data" in smb_scan._extract_text("conf", b"data")


class TestFindingType:
    """`type` carries the rule name so dedup_key (scanner|type|target) stays
    unique per (file, rule) — several distinct secrets in one file must not
    collapse into a single finding."""

    def test_default_type(self):
        f = smb_scan._finding("info", "t", "d", r"\\srv\share", {})
        assert f["type"] == "sensitive_data"

    def test_rule_type_overrides(self):
        f = smb_scan._finding("critical", "t", "d", r"\\srv\share\f.txt", {}, type_="aws_access_key")
        assert f["type"] == "aws_access_key"
        assert f["scanner"] == "smb_scan"

    def test_distinct_rules_distinct_types(self):
        # two different rules on the same file path -> different dedup identity
        a = smb_scan._finding("critical", "t", "d", r"\\srv\share\f.txt", {}, type_="aws_access_key")
        b = smb_scan._finding("medium", "t", "d", r"\\srv\share\f.txt", {}, type_="jwt")
        assert a["type"] != b["type"]
        assert a["target"] == b["target"]


class TestRegistration:
    def test_registry_entry(self):
        assert smb_scan.SURFACE_SCANNERS["smb_scan"]["kinds"] == {"file_share"}
        assert smb_scan.SURFACE_SCANNERS["smb_scan"]["wants_config"] is True
        assert smb_scan.SURFACE_DEFAULT_SCANNERS["file_share"] == ["smb_scan"]

    def test_bilingual_help_doc(self):
        # In-app help travels WITH the add-on (not the core bundle), so an image
        # built without the add-on never ships it.
        doc = smb_scan.SURFACE_SCANNERS["smb_scan"]["doc"]
        for lang in ("fr", "en"):
            assert doc[lang]["methodo"].strip().startswith("<h2>")
            assert doc[lang]["usage"].strip().startswith("<h2>")
