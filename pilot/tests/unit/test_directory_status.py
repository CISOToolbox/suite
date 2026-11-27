"""FEAT-74 lot 3a — a person's activity and contract are two notions: the
status (recrutement, actif, inactif) and the contract type (interne,
externe, alternant, stagiaire)."""
from __future__ import annotations

import os
import sys

import pytest
from fastapi import HTTPException

os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import directory as d  # noqa: E402


def test_status_and_contract_are_checked_apart():
    assert d._status("Recrutement", "Externe") == ("recrutement", "externe")
    assert d._status("", "") == ("actif", "")                                   # contract not given
    assert d._status(None, "stagiaire", ("inactif", "interne")) == ("inactif", "stagiaire")     # a change keeps the rest


def test_the_former_external_status_is_an_active_external_contract():
    assert d._status("externe", "") == ("actif", "externe")
    assert d._status("externe", "alternant") == ("actif", "alternant")


@pytest.mark.parametrize("statut, contrat", [("ancien", ""), ("actif", "salarie"), ("present", "interne")])
def test_an_unknown_status_or_contract_is_refused(statut, contrat):
    with pytest.raises(HTTPException) as e:
        d._status(statut, contrat)
    assert e.value.status_code == 422


class _OneDb:
    def __init__(self, person):
        self.person = person

    async def get(self, _model, _id):
        return self.person

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


@pytest.mark.asyncio
async def test_a_change_of_contract_keeps_the_status_and_is_broadcast(monkeypatch):
    sent = []

    async def push(_db, payload, exclude_module=None):
        sent.append(payload)
    monkeypatch.setattr(d, "_push_personnel_to_modules", push)
    p = d.Personnel(id=d.uuid.uuid4(), email="c@m.example", nom="Bernard", prenom="Claire", statut="recrutement",
                    type_contrat="interne", sync_source="")
    await d.update_personnel(p.id, {"type_contrat": "externe"}, user=None, db=_OneDb(p))
    assert (p.statut, p.type_contrat) == ("recrutement", "externe")
    assert sent[-1]["personnel"]["type_contrat"] == "externe"
    with pytest.raises(HTTPException):
        await d.update_personnel(p.id, {"statut": "ancien"}, user=None, db=_OneDb(p))


def test_a_contract_nobody_gave_stays_empty_so_the_modules_keep_theirs():
    assert d._status("actif", "") == ("actif", "")
    assert d._status("inactif", None, ("actif", "")) == ("inactif", "")
    p = d.Personnel(email="x@m.example", statut="actif", type_contrat="")
    assert d._to_dict(p)["type_contrat"] == ""


@pytest.mark.asyncio
async def test_not_given_can_be_chosen_again(monkeypatch):
    async def push(_db, payload, exclude_module=None):
        pass
    monkeypatch.setattr(d, "_push_personnel_to_modules", push)
    p = d.Personnel(id=d.uuid.uuid4(), email="c@m.example", statut="actif", type_contrat="externe", sync_source="")
    await d.update_personnel(p.id, {"statut": "actif", "type_contrat": ""}, user=None, db=_OneDb(p))
    assert p.type_contrat == ""
    await d.update_personnel(p.id, {"statut": "inactif"}, user=None, db=_OneDb(p))       # not sent: unchanged
    assert (p.statut, p.type_contrat) == ("inactif", "")
