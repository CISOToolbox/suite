"""FEAT-74 lot 2 — the directory keeps the departure date of a person who
left, and gives the people who left to a module that asks for them."""
from __future__ import annotations

import os
import sys

import pytest
from fastapi import HTTPException

os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes import directory as d  # noqa: E402


def test_a_departure_date_is_kept_for_a_person_who_left_only():
    assert d._departure("inactif", "2026-10-31") == "2026-10-31"
    assert d._departure("actif", "2026-10-31") is None
    assert d._departure("externe", "2026-10-31") is None
    assert d._departure("inactif", "") is None


@pytest.mark.parametrize("value", ["31/10/2026", "20261031", "2026-W44-6", "2026-13-01"])
def test_a_departure_that_is_not_a_plain_date_is_refused(value):
    with pytest.raises(HTTPException) as e:
        d._departure("inactif", value)
    assert e.value.status_code == 422


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _Db:
    """Records the query and answers the people it would select."""
    def __init__(self, people):
        self.people, self.query = people, None

    async def execute(self, query):
        self.query = str(query.compile(compile_kwargs={"literal_binds": True}))
        keep = self.people if "inactif" not in self.query else [p for p in self.people if p.statut != "inactif"]
        return _Rows(keep)


def _person(email, statut, date_depart=None):
    return d.Personnel(email=email, nom="", prenom="", statut=statut, date_depart=date_depart)


class _Request:
    headers = {"X-Service-Token": os.environ["SERVICE_TOKEN"]}


@pytest.mark.asyncio
async def test_the_people_who_left_are_given_only_to_a_module_that_asks(monkeypatch):
    monkeypatch.setattr(d, "SERVICE_TOKEN", os.environ["SERVICE_TOKEN"])
    people = [_person("a@m.example", "actif"), _person("p@m.example", "inactif", "2026-10-31")]
    plain = await d.internal_directory(_Request(), db=_Db(people))
    assert [p["email"] for p in plain] == ["a@m.example"]
    full = await d.internal_directory(_Request(), include_inactive=True, db=_Db(people))
    assert [(p["email"], p["date_depart"]) for p in full] == [("a@m.example", None), ("p@m.example", "2026-10-31")]


def test_an_import_keeps_a_person_whose_departure_it_cannot_read():
    assert d._csv_departure("Inactif", "2026-10-31") == "2026-10-31"       # any case
    assert d._csv_departure("inactif", "31/10/2026") is None


class _OneDb:
    """The person updated: found, committed, refreshed."""
    def __init__(self, person):
        self.person = person

    async def get(self, _model, _id):
        return self.person

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


@pytest.mark.asyncio
async def test_a_change_keeps_the_departure_unless_the_person_comes_back(monkeypatch):
    sent = []

    async def push(_db, payload, exclude_module=None):
        sent.append(payload)
    monkeypatch.setattr(d, "_push_personnel_to_modules", push)
    paul = d.Personnel(id=d.uuid.uuid4(), email="p@m.example", nom="Leroy", prenom="Paul", statut="inactif",
                       date_depart="2026-10-31", sync_source="")
    db = _OneDb(paul)
    await d.update_personnel(paul.id, {"fonction": "Dev"}, user=None, db=db)            # date not sent: kept
    assert paul.date_depart == "2026-10-31" and sent[-1]["personnel"]["date_depart"] == "2026-10-31"
    await d.update_personnel(paul.id, {"statut": "actif"}, user=None, db=db)            # back: no departure
    assert paul.date_depart is None and sent[-1]["personnel"]["date_depart"] is None


class _FindDb:
    def __init__(self, person):
        self.person = person

    async def execute(self, _query):
        person = self.person

        class _R:
            def scalar_one_or_none(self):
                return person
        return _R()


@pytest.mark.asyncio
async def test_retiring_an_entry_gives_the_rename_to_broadcast():
    p = d.Personnel(id=d.uuid.uuid4(), email="p@m.example", nom="Leroy", prenom="Paul", statut="actif", sync_source="")
    change = await d._retire_directory_entry(_FindDb(p), "P@m.example")
    assert change["action"] == "upsert" and change["old_email"] == "p@m.example"
    assert change["personnel"]["statut"] == "inactif" and change["personnel"]["email"].endswith(".invalid")
    assert change["personnel"]["date_depart"] == d.date.today().isoformat()
    fed = d.Personnel(id=d.uuid.uuid4(), email="a@m.example", statut="actif", sync_source="access")
    assert await d._retire_directory_entry(_FindDb(fed), "a@m.example") is None
