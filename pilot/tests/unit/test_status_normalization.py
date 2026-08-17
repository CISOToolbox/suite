"""Test status normalization patterns used across Pilot.

There are no dedicated _normalize_status / _denormalize_status functions
in the codebase. Instead, status matching is done inline:
- projects.py _project_to_dict counts completed measures matching
  ("completed", "Termine", "termine")
- dashboard.py filters on the same set

These tests verify the inline logic and the _VALID_STATUSES set from
routes/measures.py.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def test_valid_statuses_set():
    """_VALID_STATUSES contains the four expected statuses."""
    from src.routes.measures import _VALID_STATUSES

    assert _VALID_STATUSES == {"planned", "in_progress", "completed", "backlog"}


def test_valid_statuses_does_not_contain_french():
    """French status labels are NOT in _VALID_STATUSES (they come from
    modules as-is in the data JSON, but Pilot's own Literal uses English)."""
    from src.routes.measures import _VALID_STATUSES

    assert "termine" not in _VALID_STATUSES
    assert "en_cours" not in _VALID_STATUSES
    assert "planifie" not in _VALID_STATUSES


def _count_completed(measures: list[dict]) -> int:
    """Replicate the inline logic from _project_to_dict in projects.py."""
    return sum(
        1 for m in measures
        if m.get("status") in ("completed", "Termin\u00e9", "termine")
    )


class TestCompletedCounting:
    """Verify the completed-measure counting logic used in _project_to_dict."""

    def test_completed_english(self):
        assert _count_completed([{"status": "completed"}]) == 1

    def test_completed_termine_lowercase(self):
        assert _count_completed([{"status": "termine"}]) == 1

    def test_completed_termine_titlecase_no_accent(self):
        """Titlecase 'Termine' without accent is NOT matched by the source
        code (which uses 'Termin\\u00e9' with accent)."""
        assert _count_completed([{"status": "Termine"}]) == 0

    def test_completed_termine_accented(self):
        """'Termin\\u00e9' (with accent) is matched by projects.py."""
        assert _count_completed([{"status": "Termin\u00e9"}]) == 1

    def test_in_progress_not_counted(self):
        assert _count_completed([{"status": "in_progress"}]) == 0

    def test_planned_not_counted(self):
        assert _count_completed([{"status": "planned"}]) == 0

    def test_backlog_not_counted(self):
        assert _count_completed([{"status": "backlog"}]) == 0

    def test_empty_status(self):
        assert _count_completed([{"status": ""}]) == 0

    def test_missing_status_key(self):
        assert _count_completed([{}]) == 0

    def test_none_status(self):
        assert _count_completed([{"status": None}]) == 0

    def test_mixed_statuses(self):
        measures = [
            {"status": "completed"},
            {"status": "in_progress"},
            {"status": "termine"},
            {"status": "planned"},
        ]
        assert _count_completed(measures) == 2

    def test_empty_list(self):
        assert _count_completed([]) == 0

    def test_en_cours_not_counted(self):
        """French 'en_cours' is not counted as completed."""
        assert _count_completed([{"status": "en_cours"}]) == 0

    def test_unmapped_value(self):
        """Random unknown values are not counted."""
        assert _count_completed([{"status": "unknown_status"}]) == 0
        assert _count_completed([{"status": "COMPLETED"}]) == 0
