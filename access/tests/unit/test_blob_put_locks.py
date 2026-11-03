"""Regression: the project blob PUT honours the locks of the granular routes.

`routes/reviews.py` refuses any change to a closed access review, refuses to
close one with pending entries and assigns `closed_by` itself;
`routes/si_users.py` refuses to edit the identity of a Pilot-managed user.
The blob PUT deleted and rebuilt every row from the client JSON, so a GET,
an edit and a PUT lifted all of these.
"""
import asyncio
import copy
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import audit  # noqa: E402
from src.routes import projects  # noqa: E402


def _entry(eid, decision="conforme", **kw):
    e = {"id": eid, "type_compte": "personnel", "email_or_login": f"{eid}@medsecure.example",
         "nom": "Durand", "prenom": "Claire", "roles": "reader", "groups": "", "si_user_id": None,
         "decision": decision, "decided_by": "Claire Durand", "decided_at": "2026-10-01",
         "notes": "", "last_login_at": "2026-09-30T08:00:00+00:00", "account_enabled": True}
    e.update(kw)
    return e


def _review(rid, status, entries, **kw):
    r = {"id": rid, "application_id": "APP-1", "status": status, "started_at": "2026-09-01",
         "closed_at": "2026-10-02" if status != "en_cours" else "",
         "closed_by": "Claire Durand" if status != "en_cours" else "", "entries": entries}
    r.update(kw)
    return r


def _si_user(uid, sync_source=""):
    return {"id": uid, "nom": "Martin", "prenom": "Paul", "email": "paul.martin@medsecure.example",
            "statut": "actif", "type_compte": "salarie", "fonction": "Biomedical engineer",
            "equipe": "R&D", "sync_source": sync_source}


STORED = {
    "metadata": {"organization": "MedSecure", "created": ""},
    "si_users": [_si_user("U-1", "pilot"), _si_user("U-2")],
    "applications": [{"id": "APP-1", "nom": "Patient portal"}, {"id": "APP-2", "nom": "Lab LIMS"}],
    "reviews": [
        _review("REV-1", "cloturee", [_entry("E-1"), _entry("E-2", "non_conforme")]),
        _review("REV-2", "en_cours", [_entry("E-3"), _entry("E-4", "pending")]),
        _review("REV-3", "en_cours", [_entry("E-5")]),
    ],
    "measures": [],
    "service_accounts": [],
}

CLOSER = SimpleNamespace(id=uuid.uuid4(), name="Alice Bernard", email="alice.bernard@medsecure.example",
                         role="admin", _module_role="admin")
MANAGER = SimpleNamespace(id=uuid.uuid4(), name="Marc Petit", email="marc.petit@medsecure.example",
                          role="user", _module_role="manager")   # read + edit, no delete


class _DB:
    async def get(self, _model, _id):
        return SimpleNamespace(id=_id, name="MedSecure", organization="MedSecure", owner_id=None,
                               shared_with=[], updated_at=None, server_rev=0)

    async def commit(self):
        pass

    async def refresh(self, _obj):
        pass


@pytest.fixture
def put(monkeypatch):
    written = {}

    async def _reconstruct(_db, _pid):
        return copy.deepcopy(written.get("stored", STORED))

    async def _noop(*_a, **_k):
        return None

    async def _decompose(_db, _pid, data):
        written["data"] = data

    monkeypatch.setattr(projects, "_reconstruct_data", _reconstruct)
    monkeypatch.setattr(projects, "_delete_children", _noop)
    monkeypatch.setattr(projects, "_decompose_data", _decompose)
    monkeypatch.setattr(projects, "_project_response", lambda p, d: {})
    monkeypatch.setattr(audit, "log_write", _noop)
    revoked = []

    async def _revoke(_db, _pid, review_id, entry_ids, actor):
        revoked.append((review_id, sorted(entry_ids), actor))

    monkeypatch.setattr(projects, "revoke_review_derogations", _revoke, raising=False)

    def _put(data, user=CLOSER, expected_server_rev=None, stored=None):
        if stored is not None:
            written["stored"] = stored
        body = SimpleNamespace(name=None, organization=None, data=data, expected_server_rev=expected_server_rev)
        asyncio.run(projects.update_project(uuid.uuid4(), body, user, _DB()))
        return written["data"]
    _put.revoked = revoked
    return _put


def _blob():
    return copy.deepcopy(STORED)


def _review_of(data, rid):
    return next(r for r in data["reviews"] if r["id"] == rid)


# ── closed review ────────────────────────────────────────────────────

@pytest.mark.parametrize("change", [
    lambda r: r["entries"][1].update(decision="conforme"),
    lambda r: r["entries"][0].update(notes="rewritten"),
    lambda r: r["entries"].pop(),
    lambda r: r["entries"].append(_entry("E-9")),
    lambda r: r.update(closed_by="Someone Else"),
    lambda r: r.update(closed_at="2026-01-01"),
    lambda r: r.update(status="en_cours"),
], ids=["decision", "notes", "drop-entry", "add-entry", "closed_by", "closed_at", "reopen"])
def test_closed_review_cannot_change(put, change):
    data = _blob()
    change(_review_of(data, "REV-1"))
    with pytest.raises(HTTPException) as exc:
        put(data)
    assert exc.value.status_code == 409


def test_resending_the_stored_blob_is_accepted(put):
    data = _blob()
    _review_of(data, "REV-1")["entries"].reverse()   # display order is not a change
    out = put(data)
    assert _review_of(out, "REV-1")["closed_by"] == "Claire Durand"


# ── deleting an application takes its reviews ────────────────────────

def _without_app(data, app_id):
    data["applications"] = [a for a in data["applications"] if a["id"] != app_id]
    data["reviews"] = [r for r in data["reviews"] if r["application_id"] != app_id]
    return data


def test_deleting_the_application_drops_its_closed_review(put):
    out = put(_without_app(_blob(), "APP-1"))
    assert [r["id"] for r in out["reviews"]] == []


def test_application_already_deleted_drops_its_closed_review(put):
    # Bulk delete: DELETE /applications/APP-1 ran first, then the blob follows.
    stored = _blob()
    stored["applications"] = [a for a in stored["applications"] if a["id"] != "APP-1"]
    out = put(_without_app(_blob(), "APP-1"), stored=stored)
    assert "REV-1" not in [r["id"] for r in out["reviews"]]


def test_without_delete_right_the_closed_review_stays(put):
    with pytest.raises(HTTPException) as exc:
        put(_without_app(_blob(), "APP-1"), user=MANAGER)
    assert exc.value.status_code == 409


def test_application_kept_the_closed_review_stays(put):
    data = _blob()
    data["reviews"] = [r for r in data["reviews"] if r["id"] != "REV-1"]
    with pytest.raises(HTTPException) as exc:
        put(data)
    assert exc.value.status_code == 409


# ── conflict marker ──────────────────────────────────────────────────

def test_stale_conflict_is_marked(put):
    with pytest.raises(HTTPException) as exc:
        put(_blob(), expected_server_rev=-1)
    assert exc.value.status_code == 409
    assert (exc.value.headers or {}).get("X-CT-Conflict") == "stale"


def test_lock_conflict_is_not_marked_stale(put):
    data = _blob()
    _review_of(data, "REV-1")["entries"][0]["notes"] = "rewritten"
    with pytest.raises(HTTPException) as exc:
        put(data)
    assert (exc.value.headers or {}).get("X-CT-Conflict") != "stale"


# ── closing through the blob ─────────────────────────────────────────

def test_closing_with_pending_entries_is_refused(put):
    data = _blob()
    _review_of(data, "REV-2").update(status="cloturee", closed_at="2026-10-05", closed_by="Claire Durand")
    with pytest.raises(HTTPException) as exc:
        put(data)
    assert exc.value.status_code == 409


def test_closer_and_date_are_server_assigned(put):
    data = _blob()
    _review_of(data, "REV-3").update(status="cloturee", closed_at="2020-01-01", closed_by="Someone Else")
    r = _review_of(put(data), "REV-3")
    assert r["closed_by"] == "Alice Bernard"
    assert r["closed_at"] == projects._today()


@pytest.mark.parametrize("status", ["xyz", "planifiee", "CLOTUREE"])
def test_unknown_review_status_is_refused(put, status):
    data = _blob()
    _review_of(data, "REV-3")["status"] = status
    with pytest.raises(HTTPException) as exc:
        put(data)
    assert exc.value.status_code == 422


def test_open_review_carries_no_closer(put):
    data = _blob()
    _review_of(data, "REV-3").update(closed_by="Someone Else", closed_at="2020-01-01")
    r = _review_of(put(data), "REV-3")
    assert r["closed_by"] == "" and r["closed_at"] == ""


# ── Pilot-managed identity ───────────────────────────────────────────

@pytest.mark.parametrize("field,value", [
    ("nom", "Intrus"), ("prenom", "Eve"), ("email", "eve@evil.example"),
    ("fonction", "Admin"), ("statut", "ancien"), ("sync_source", ""),
])
def test_pilot_identity_is_kept(put, field, value):
    data = _blob()
    data["si_users"][0][field] = value
    u = put(data)["si_users"][0]
    assert u[field] == STORED["si_users"][0][field]


def test_pilot_user_other_fields_stay_editable(put):
    data = _blob()
    data["si_users"][0]["equipe"] = "Quality"
    data["si_users"][1]["nom"] = "Leroy"
    out = put(data)["si_users"]
    assert out[0]["equipe"] == "Quality"
    assert out[1]["nom"] == "Leroy"


# ── a dropped review settles the derogations on its entries ──────────

def test_dropped_reviews_revoke_their_derogations(put):
    put(_without_app(_blob(), "APP-1"))   # every review of the fixture is on APP-1
    assert put.revoked == [("REV-1", ["E-1", "E-2"], "Alice Bernard"),
                           ("REV-2", ["E-3", "E-4"], "Alice Bernard"),
                           ("REV-3", ["E-5"], "Alice Bernard")]


def test_kept_reviews_revoke_nothing(put):
    put(_blob())
    assert put.revoked == []
