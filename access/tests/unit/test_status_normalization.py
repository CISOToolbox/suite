import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from routes.internal import _normalize_status


class TestNormalizeStatus:
    def test_termine_lowercase(self):
        assert _normalize_status("termine") == "completed"

    def test_termine_capitalized(self):
        assert _normalize_status("Termine") == "completed"

    def test_termine_accented(self):
        """Regression: accented 'Termine' must map to 'completed'."""
        assert _normalize_status("Terminé") == "completed"

    def test_completed_passthrough(self):
        assert _normalize_status("completed") == "completed"

    def test_en_cours_snake(self):
        assert _normalize_status("en_cours") == "in_progress"

    def test_en_cours_spaced(self):
        assert _normalize_status("En cours") == "in_progress"

    def test_in_progress_passthrough(self):
        assert _normalize_status("in_progress") == "in_progress"

    def test_a_faire(self):
        assert _normalize_status("a_faire") == "planned"

    def test_planifie(self):
        assert _normalize_status("planifie") == "planned"

    def test_planned_passthrough(self):
        assert _normalize_status("planned") == "planned"

    def test_unknown_passthrough(self):
        assert _normalize_status("something_else") == "something_else"

    def test_empty_string(self):
        assert _normalize_status("") == ""
