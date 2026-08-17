import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from routes.si_users import _CSV_COL_MAP, _CSV_STATUT_MAP, _CSV_TYPE_MAP


def _norm(header: str) -> str:
    """Mirror the header normalisation done in import_si_users_csv."""
    return header.strip().lower().replace(" ", "_").replace("-", "_")


class TestCsvColumnMapping:
    def test_identity_headers(self):
        assert _CSV_COL_MAP[_norm("Nom")] == "nom"
        assert _CSV_COL_MAP[_norm("Prénom")] == "prenom"
        assert _CSV_COL_MAP[_norm("First Name")] == "prenom"
        assert _CSV_COL_MAP[_norm("E-mail")] == "email"

    def test_new_referential_headers(self):
        assert _CSV_COL_MAP[_norm("Équipe")] == "equipe"
        assert _CSV_COL_MAP[_norm("Team")] == "equipe"
        assert _CSV_COL_MAP[_norm("Date fin contrat")] == "date_fin_contrat"
        assert _CSV_COL_MAP[_norm("end_date")] == "date_fin_contrat"
        assert _CSV_COL_MAP[_norm("Manager")] == "manager_email"
        assert _CSV_COL_MAP[_norm("Responsable hierarchique")] == "manager_email"


class TestCsvTypeNormalization:
    def test_salarie_variants(self):
        assert _CSV_TYPE_MAP["salarié"] == "salarie"
        assert _CSV_TYPE_MAP["employee"] == "salarie"

    def test_other_types(self):
        assert _CSV_TYPE_MAP["contractor"] == "prestataire"
        assert _CSV_TYPE_MAP["intern"] == "stagiaire"
        assert _CSV_TYPE_MAP["apprenti"] == "alternant"


class TestCsvStatutNormalization:
    def test_statut_variants(self):
        assert _CSV_STATUT_MAP["active"] == "actif"
        assert _CSV_STATUT_MAP["inactif"] == "ancien"
        assert _CSV_STATUT_MAP["onboarding"] == "recrutement"
