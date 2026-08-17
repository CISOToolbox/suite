"""Design regression (H2): Pilot must count criticals from the semantic
`criticals` field, not by parsing localized breakdown labels.

The old heuristic matched segment/bucket labels ("Critique"/"Élevé"/…), so a
module's i18n or cosmetic relabel silently zeroed a top-level KPI, and Pilot
needed per-module knowledge of each breakdown shape. Modules now emit a
top-level `criticals` int; the label heuristic survives only as a fallback for
a not-yet-updated module.
"""
from src.routes.dashboard import _count_critical


def test_semantic_field_is_preferred_over_labels():
    stats = {
        "criticals": 7,
        # A legacy breakdown that would yield a DIFFERENT number is ignored.
        "breakdown": {"type": "donut", "data": {"segments": [
            {"label": "Critique", "value": 1},
            {"label": "Élevé", "value": 1},
        ]}},
    }
    assert _count_critical("risk", stats) == 7


def test_semantic_field_zero_is_respected():
    assert _count_critical("surface", {"criticals": 0, "breakdown": {
        "type": "bar", "data": {"buckets": [{"label": "Critical", "value": 5}]}}}) == 0


def test_bool_is_not_treated_as_a_count():
    # True is an int subclass — must not be read as criticals=1.
    stats = {"criticals": True, "breakdown": {"type": "donut", "data": {"segments": [
        {"label": "Critique", "value": 3}]}}}
    assert _count_critical("risk", stats) == 3  # falls through to the legacy path


def test_legacy_fallback_risk_donut():
    stats = {"breakdown": {"type": "donut", "data": {"segments": [
        {"label": "Critique", "value": 2},
        {"label": "Élevé", "value": 3},
        {"label": "Modéré", "value": 9},
    ]}}}
    assert _count_critical("risk", stats) == 5


def test_legacy_fallback_surface_bar():
    stats = {"breakdown": {"type": "bar", "data": {"buckets": [
        {"label": "Critical", "value": 4},
        {"label": "High", "value": 1},
        {"label": "Low", "value": 20},
    ]}}}
    assert _count_critical("surface", stats) == 5


def test_non_dict_and_unknown_module():
    assert _count_critical("risk", None) == 0
    assert _count_critical("access", {"breakdown": {"type": "donut", "data": {}}}) == 0
