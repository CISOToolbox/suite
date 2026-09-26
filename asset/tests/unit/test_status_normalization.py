import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


class TestStatusNormalization:
    """Asset measures carry a status, mapped to Pilot's transverse vocabulary
    by _normalize_status (routes/internal.py) for the consolidated view."""

    def test_known_statuses_are_mapped(self):
        from routes.internal import _normalize_status
        assert _normalize_status("termine") == "completed"
        assert _normalize_status("Terminé") == "completed"
        assert _normalize_status("en_cours") == "in_progress"
        assert _normalize_status("a_faire") == "planned"
        assert _normalize_status("planifie") == "planned"

    def test_unknown_status_passes_through(self):
        from routes.internal import _normalize_status
        assert _normalize_status(" abandonne ") == " abandonne "
        assert _normalize_status("") == ""

    def test_posture_label_exists(self):
        """Asset does have _posture_label for the stats endpoint."""
        from routes.internal import _posture_label
        assert callable(_posture_label)

    def test_posture_label_thresholds(self):
        from routes.internal import _posture_label
        assert _posture_label(None) == ""
        assert _posture_label(0) == "Faible"
        assert _posture_label(39) == "Faible"
        assert _posture_label(40) == "Modéré"
        assert _posture_label(59) == "Modéré"
        assert _posture_label(60) == "Bon"
        assert _posture_label(79) == "Bon"
        assert _posture_label(80) == "Excellent"
        assert _posture_label(100) == "Excellent"
