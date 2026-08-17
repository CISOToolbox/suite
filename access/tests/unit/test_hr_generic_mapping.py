import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from plugins.hr_generic import _extract_list, _map_employee


class TestMapEmployee:
    def test_aliases_fr_en(self):
        rec = {
            "First Name": "Marc", "Last Name": "Lefevre", "Work Email": "m@x.fr",
            "Job Title": "Dev", "Department": "Plateforme", "Manager": "c@x.fr",
            "Contract End": "2026-12-31", "Employee Type": "prestataire", "Status": "actif",
        }
        out = _map_employee(rec)
        assert out["email"] == "m@x.fr"
        assert out["prenom"] == "Marc"
        assert out["nom"] == "Lefevre"
        assert out["fonction"] == "Dev"
        assert out["equipe"] == "Plateforme"
        assert out["manager_email"] == "c@x.fr"
        assert out["date_fin_contrat"] == "2026-12-31"
        assert out["type_compte"] == "prestataire"
        assert out["statut"] == "actif"

    def test_accented_keys(self):
        out = _map_employee({"prénom": "Sofia", "équipe": "Sécurité", "email": "s@x.fr"})
        assert out["prenom"] == "Sofia"
        assert out["equipe"] == "Sécurité"

    def test_missing_email_defaults_empty(self):
        assert _map_employee({"nom": "X"})["email"] == ""

    def test_nested_values_ignored(self):
        out = _map_employee({"email": "a@b.fr", "manager": {"id": 1}, "roles": ["x"]})
        assert out["email"] == "a@b.fr"
        assert "manager_email" not in out


class TestExtractList:
    def test_plain_list(self):
        assert _extract_list([{"a": 1}, "skip", {"b": 2}]) == [{"a": 1}, {"b": 2}]

    def test_wrapped_known_keys(self):
        assert _extract_list({"results": [{"a": 1}]}) == [{"a": 1}]
        assert _extract_list({"employees": [{"b": 2}]}) == [{"b": 2}]

    def test_configured_key(self):
        assert _extract_list({"rows": [{"a": 1}]}, users_key="rows") == [{"a": 1}]

    def test_unknown_returns_empty(self):
        assert _extract_list({"nope": 1}) == []
        assert _extract_list("string") == []
