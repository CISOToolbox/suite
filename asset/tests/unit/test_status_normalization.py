import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


class TestNoStatusNormalization:
    """Asset module has no _normalize_status function in routes/internal.py.

    Asset does not have measures with status fields, so there is no status
    normalization logic. This test documents that expectation.
    """

    def test_normalize_status_not_present(self):
        from routes import internal
        assert not hasattr(internal, '_normalize_status'), (
            "_normalize_status should not exist in asset/routes/internal.py — "
            "asset has no measure status to normalize"
        )

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
