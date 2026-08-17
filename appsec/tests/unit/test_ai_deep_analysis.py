"""Regression guards for the AI triage enhancements:
  - language-aware system prompt (summary/remediation localized),
  - untrusted repo-path validation for deep source-code analysis,
  - network-free early returns of fetch_file_window (note codes).

These lock the security-critical path logic and the prompt contract without
needing a live repo, AI provider or database.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.scanners import _safe_rel_path, fetch_file_window  # noqa: E402
from src.routes.ai import _finding_analysis_system  # noqa: E402


class TestSafeRelPath:
    def test_accepts_normal_relative_path(self):
        assert _safe_rel_path("src/app/main.py") == "src/app/main.py"

    def test_strips_leading_slash(self):
        # An absolute-looking path is de-fanged to repo-relative.
        assert _safe_rel_path("/etc/passwd") == "etc/passwd"

    def test_collapses_dot_and_empty_segments(self):
        assert _safe_rel_path("./src/./x.py") == "src/x.py"

    def test_normalizes_backslashes(self):
        assert _safe_rel_path("src\\pkg\\x.py") == "src/pkg/x.py"

    def test_rejects_parent_traversal(self):
        for bad in ["..", "../etc/passwd", "src/../../etc", "a/../../b"]:
            assert _safe_rel_path(bad) is None, bad

    def test_rejects_empty_and_blank(self):
        assert _safe_rel_path("") is None
        assert _safe_rel_path("   ") is None
        assert _safe_rel_path("/") is None

    def test_rejects_nul_byte(self):
        assert _safe_rel_path("a\x00b.py") is None


class TestFetchFileWindowEarlyReturns:
    """Branches that return before any git/network I/O."""

    def test_unsafe_path_returns_path_code(self):
        r = fetch_file_window("https://host/repo", "main", "", "", "../x.py", 1)
        assert r == {"ok": False, "note": "path"}

    def test_non_url_repo_returns_no_repo(self):
        # Empty token → decrypt returns "" without a key; injected url keeps no
        # scheme → treated as "no repository".
        r = fetch_file_window("not-a-url", "main", "", "", "src/x.py", 1)
        assert r == {"ok": False, "note": "no_repo"}

    def test_undecryptable_token_returns_token_code(self, monkeypatch):
        # Simulate a stored PAT that no longer decrypts (ENCRYPTION_KEY rotated).
        monkeypatch.setattr("src.scanners.decrypt_token", lambda _c: "")
        r = fetch_file_window("https://host/repo", "main", "", "ciphertext",
                              "src/x.py", 1)
        assert r == {"ok": False, "note": "token"}


class TestFindingAnalysisSystemLanguage:
    def test_french_prompt_requests_french_prose(self):
        s = _finding_analysis_system("fr")
        assert "French" in s
        assert "English" in s  # keys/enums stay English

    def test_english_prompt_requests_english_prose(self):
        s = _finding_analysis_system("en")
        assert "in English" in s

    def test_unknown_language_defaults_to_french(self):
        assert "French" in _finding_analysis_system("de")

    def test_default_argument_is_french(self):
        assert "French" in _finding_analysis_system()

    def test_prompt_pins_json_keys_and_enums_to_english(self):
        s = _finding_analysis_system("fr")
        assert "Keep the JSON keys" in s
        assert '"is_probable_false_positive"' in s
