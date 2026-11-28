"""FEAT-74 lot 3a — Access takes Pilot's status and contract type as they
are: two notions, the same words on both sides."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes.si_users import pilot_status  # noqa: E402


def test_status_and_contract_pass_as_they_are():
    assert pilot_status({"statut": "inactif", "type_contrat": "stagiaire"}) == ("inactif", "stagiaire")
    assert pilot_status({"statut": "Recrutement", "type_contrat": "Externe"}) == ("recrutement", "externe")


def test_the_former_external_status_is_an_active_external_contract():
    assert pilot_status({"statut": "externe"}) == ("actif", "externe")


def test_a_value_access_does_not_know_keeps_the_current_one():
    assert pilot_status({"statut": "ancien", "type_contrat": ""}, ("inactif", "alternant")) == ("inactif", "alternant")
    assert pilot_status({}) == ("actif", "interne")
