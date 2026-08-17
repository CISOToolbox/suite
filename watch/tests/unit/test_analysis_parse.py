"""Unit tests for the LLM output parser.

The model occasionally wraps its JSON in ```json fences or returns
loose markdown. The parser must always return a dict with the full
SECTION_KEYS set so the UI never crashes on missing keys.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


def test_strict_json_passes_through():
    from analysis import _parse_sections, SECTION_KEYS
    raw = '{"executive_summary":"foo","technical_detail":"bar","exploitation_status":"x","affected_components":"y","business_impact":"z","recommended_actions":"a","references_curated":"b","confidence":"high"}'
    out = _parse_sections(raw)
    assert out["executive_summary"] == "foo"
    assert out["confidence"] == "high"
    for k in SECTION_KEYS:
        assert k in out


def test_json_with_code_fence_is_stripped():
    from analysis import _parse_sections
    raw = '```json\n{"executive_summary":"foo","confidence":"low"}\n```'
    out = _parse_sections(raw)
    assert out["executive_summary"] == "foo"
    assert out["confidence"] == "low"


def test_list_field_is_joined():
    from analysis import _parse_sections
    raw = '{"recommended_actions":["patch","rotate","monitor"]}'
    out = _parse_sections(raw)
    assert out["recommended_actions"] == "patch | rotate | monitor"


def test_non_json_falls_back_to_executive_summary():
    from analysis import _parse_sections, SECTION_KEYS
    raw = "Sorry I cannot comply"
    out = _parse_sections(raw)
    assert out["executive_summary"].startswith("Sorry")
    for k in SECTION_KEYS:
        assert k in out


def test_empty_input_returns_skeleton():
    from analysis import _parse_sections, SECTION_KEYS
    out = _parse_sections("")
    for k in SECTION_KEYS:
        assert k in out
        assert out[k] == ""


class _FakeAlert:
    source = "nvd"
    external_id = "CVE-2025-1"
    title = "Test"
    summary = "Test summary"
    severity = "high"
    cvss_score = 8.5
    kev_listed = False
    modified_at = None
    affected_json = [{"vendor": "x", "product": "y"}]
    references_json = ["https://example.com"]


def test_compute_hash_stable():
    from analysis import compute_alert_hash
    a1 = _FakeAlert()
    a2 = _FakeAlert()
    assert compute_alert_hash(a1) == compute_alert_hash(a2)


def test_compute_hash_changes_with_severity():
    from analysis import compute_alert_hash
    a1 = _FakeAlert()
    a2 = _FakeAlert()
    a2.severity = "critical"
    assert compute_alert_hash(a1) != compute_alert_hash(a2)
