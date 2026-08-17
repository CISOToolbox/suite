"""Unit tests for the FEAT-34 deadline-digest pure helpers.

The DB-bound selection is exercised live; here we lock the decision
logic: who a measure concerns, what falls in the window, and that the
rendered HTML escapes user data.
"""
import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

os.environ.setdefault("JWT_SECRET", "x" * 64)

from src.deadline_digest import (  # noqa: E402
    classify_due,
    iso_week_key,
    matches_user,
    render_digest_html,
)


class TestMatchesUser:
    def test_email_match_is_case_insensitive(self):
        assert matches_user("Julien.Petit@medsecure.fr", "julien.petit@medsecure.fr", "Julien Petit")

    def test_name_match_ignores_extra_whitespace(self):
        assert matches_user("  Julien   Petit ", "julien.petit@medsecure.fr", "Julien Petit")

    def test_unresolvable_assignee_matches_nobody(self):
        # Spec: the digest does not guess.
        assert not matches_user("CTO + QA", "julien.petit@medsecure.fr", "Julien Petit")

    def test_empty_assignee_matches_nobody(self):
        assert not matches_user("", "a@b.fr", "A B")
        assert not matches_user(None, "a@b.fr", "A B")

    def test_empty_user_name_never_matches_empty_assignee(self):
        assert not matches_user("", "a@b.fr", None)


class TestClassifyDue:
    T = date(2026, 8, 17)

    def test_overdue(self):
        assert classify_due("2026-08-10", self.T, 14) == ("overdue", 7)

    def test_today_is_upcoming_zero(self):
        assert classify_due("2026-08-17", self.T, 14) == ("upcoming", 0)

    def test_inside_window(self):
        assert classify_due("2026-08-30", self.T, 14) == ("upcoming", 13)

    def test_outside_window(self):
        assert classify_due("2026-09-15", self.T, 14) is None

    def test_unparseable_or_empty(self):
        assert classify_due("", self.T, 14) is None
        assert classify_due("bientôt", self.T, 14) is None

    def test_datetime_suffix_tolerated(self):
        # Some modules cache "YYYY-MM-DDTHH:MM:SS" — only the date part counts.
        assert classify_due("2026-08-10T00:00:00", self.T, 14) == ("overdue", 7)


class TestIsoWeekKey:
    def test_format(self):
        assert iso_week_key(date(2026, 8, 17)) == "2026-W34"

    def test_year_boundary_uses_iso_year(self):
        # 2027-01-01 belongs to ISO week 2026-W53.
        assert iso_week_key(date(2027, 1, 1)) == "2026-W53"


class TestRenderEscaping:
    def _item(self, title):
        return {"kind": "overdue", "days": 3, "due": "2026-08-14", "ref": "MES-001",
                "title": title, "modules": ["risk"], "module": "risk",
                "entity_id": "", "source_id": "MES-001", "group_id": ""}

    def test_title_is_escaped(self):
        html = render_digest_html([self._item('<script>alert(1)</script>')],
                                  "Test", "fr", 14, {}, "")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_meta_group_renders_all_module_badges(self):
        item = {"kind": "upcoming", "days": 5, "due": "2026-08-22", "ref": "META-002",
                "title": "Revue", "modules": ["risk", "access"], "module": "pilot",
                "entity_id": "", "source_id": "", "group_id": "abc"}
        html = render_digest_html([item], "Test", "en", 14, {}, "https://pilot.local")
        assert "META-002" in html and ">risk<" in html and ">access<" in html
        assert "https://pilot.local/?group=abc#measures" in html
