import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from routes.applications import _norm_roles, _norm_type


class TestNormType:
    def test_valid_passthrough(self):
        assert _norm_type("application") == "application"
        assert _norm_type("Infrastructure") == "infrastructure"
        assert _norm_type("physique") == "physique"

    def test_invalid_defaults_application(self):
        assert _norm_type("bogus") == "application"
        assert _norm_type("") == "application"
        assert _norm_type(None) == "application"


class TestNormRoles:
    def test_trims_and_drops_empty(self):
        assert _norm_roles(["Admin", "  Lecteur  ", "", "   "]) == ["Admin", "Lecteur"]

    def test_non_list_returns_empty(self):
        assert _norm_roles("Admin") == []
        assert _norm_roles(None) == []

    def test_caps_at_200(self):
        assert len(_norm_roles([f"r{i}" for i in range(300)])) == 200
