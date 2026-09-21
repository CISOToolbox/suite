"""FEAT-45 — non-conformities and derogations on review entries.

The shared mechanics are exercised through Access's own models and hook,
against SQLite: a non-compliant entry is the subject; approval marks it
derogated, expiry brings it back; the reviewer's decision lifts the
derogation; the stats envelope counts the category on its own."""
import os
import sys
import uuid
from datetime import date, timedelta

import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from starlette.requests import Request  # noqa: E402

from src.models import Application, Base, Derogation, Measure, Nonconformity, Project, Review, ReviewEntry  # noqa: E402
from src.nonconformity_common import (DecisionBody, DerogationCreate, NonconformityCreate,  # noqa: E402
                                      NonconformityPatch, QualifyBody, expire_derogations, revoke_for_subject)
from src.routes.nonconformities import ENTRY_HOOK, router  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

PID = uuid.uuid4()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add(Project(id=PID, name="MedSecure"))
        session.add(Application(project_id=PID, id="APP-001", nom="Patient portal"))
        session.add(Review(project_id=PID, id="REV-001", application_id="APP-001", status="en_cours"))
        session.add(Measure(project_id=PID, id="MES-001", title="Remove the orphan account", statut="a_faire"))
        await session.commit()
        yield session
    await engine.dispose()


def _req() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/api/derogations", "headers": [],
                    "query_string": b"", "client": ("127.0.0.1", 1)})


def _endpoint(name: str):
    for r in router.routes:
        if r.endpoint.__name__ == name:
            return r.endpoint
    raise KeyError(name)


async def _entry(db, decision="non_conforme", eid=None):
    eid = eid or f"E-{uuid.uuid4().hex[:6]}"
    e = ReviewEntry(project_id=PID, review_id="REV-001", id=eid, email_or_login="j.doe@medsecure.example", decision=decision)
    db.add(e)
    await db.commit()
    return e


def _key(e) -> str:
    return f"{PID}:REV-001:{e.id}"


def _der_body(subject_id, **over):
    body = {"subject_type": "review_entry", "subject_id": subject_id, "title": "Kept until the handover",
            "justification": "The account is needed until the contractor's handover next month; access is logged.",
            "risk_owner": "it@medsecure.example", "approver": "ciso@medsecure.example",
            "valid_until": (date.today() + timedelta(days=30)).isoformat()}
    body.update(over)
    return body


@pytest.mark.asyncio
async def test_the_hook_names_a_non_compliant_entry_only(db):
    e = await _entry(db)
    assert await ENTRY_HOOK.exists(db, "review_entry", _key(e)) == "j.doe@medsecure.example — Patient portal"
    assert await ENTRY_HOOK.exists(db, "review_entry", f"{PID}:REV-001:nope") is None
    assert await ENTRY_HOOK.exists(db, "review_entry", "garbage") is None
    ok = await _entry(db, decision="conforme")
    with pytest.raises(HTTPException) as x:
        await ENTRY_HOOK.exists(db, "review_entry", _key(ok))
    assert x.value.status_code == 409


@pytest.mark.asyncio
async def test_an_approved_derogation_marks_the_entry_until_it_expires_or_is_decided(db):
    e = await _entry(db)
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(_key(e))), _req(), user=None, db=db)
    d = await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    assert d["status"] == "approved" and d["subject_label"].startswith("j.doe@")
    await db.refresh(e)
    assert e.decision == "derogated"
    der = await db.get(Derogation, uuid.UUID(d["id"]))
    der.valid_until = date.today() - timedelta(days=1)
    await db.commit()
    assert await expire_derogations(db, Derogation, ENTRY_HOOK, Nonconformity) == 1
    await db.refresh(e)
    assert e.decision == "non_conforme" and "expired" in (e.notes or "")
    # the reviewer's decision supersedes a live derogation (what patch_entry does)
    d2 = await _endpoint("request_derogation")(DerogationCreate(**_der_body(_key(e))), _req(), user=None, db=db)
    await _endpoint("decide_derogation")(d2["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    await revoke_for_subject(db, Derogation, "review_entry", _key(e), "entry decided 'conforme'", actor="reviewer")
    await db.commit()
    assert (await db.get(Derogation, uuid.UUID(d2["id"]))).status == "revoked"


@pytest.mark.asyncio
async def test_a_record_concerns_entries_and_project_measures(db):
    e1, e2 = await _entry(db), await _entry(db)
    n = await _endpoint("declare_nonconformity")(
        NonconformityCreate(title="Orphan accounts kept after departure",
                            subjects=[{"type": "review_entry", "id": _key(e1)}, {"type": "review_entry", "id": _key(e2)}]),
        _req(), user=None, db=db)
    assert [x["id"] for x in n["subjects"]] == [_key(e1), _key(e2)]
    await _endpoint("qualify_nonconformity")(n["id"], QualifyBody(), user=None, db=db)
    r = await _endpoint("patch_nonconformity")(n["id"], NonconformityPatch(measure_ids=[f"{PID}:MES-001"]), user=None, db=db)
    assert r["status"] == "in_remediation"
    with pytest.raises(HTTPException) as x:
        await _endpoint("patch_nonconformity")(n["id"], NonconformityPatch(measure_ids=[f"{PID}:MES-404"]), user=None, db=db)
    assert x.value.status_code == 422


@pytest.mark.asyncio
async def test_stats_envelope_counts_the_category(db):
    from src.routes.internal import internal_stats
    e = await _entry(db)
    await _entry(db)                                        # a second anomaly, still open
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(_key(e))), _req(), user=None, db=db)
    await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    await _endpoint("declare_nonconformity")(NonconformityCreate(title="Declared, waiting"), _req(), user=None, db=db)
    db.expunge_all()
    sreq = Request({"type": "http", "method": "GET", "path": "/api/internal/stats", "query_string": b"",
                    "headers": [(b"x-service-token", os.environ["SERVICE_TOKEN"].encode())], "client": ("127.0.0.1", 1)})
    stats = await internal_stats(sreq, db)
    assert stats["nonconformities"] == {"derogated": 1, "detected_open": 1, "with_measure": 0, "to_qualify": 1, "open": 0}


@pytest.mark.asyncio
async def test_the_register_is_scoped_to_the_project_and_to_the_role(db, monkeypatch):
    """Access's own gates on the register: a read-only account writes nothing,
    an entry of another project is not a valid object, and only an
    administrator (or the internal-controls team) decides."""
    import src.auth_common as auth_common
    from types import SimpleNamespace
    from src.nonconformity_common import DecisionBody
    monkeypatch.setattr(auth_common, "auth_enabled", lambda: True)

    owner = uuid.uuid4()
    project = await db.get(Project, PID)
    project.owner_id = owner
    elsewhere = uuid.uuid4()
    db.add(Project(id=elsewhere, name="Another perimeter", owner_id=owner))
    await db.commit()
    viewer = SimpleNamespace(id=uuid.uuid4(), name="Vera Viewer", email="vera@medsecure.example", role="admin", _module_role="viewer")
    editor = SimpleNamespace(id=uuid.uuid4(), name="Ed Editor", email="ed@medsecure.example", role="user", _module_role="editor")
    control = SimpleNamespace(id=uuid.uuid4(), name="Cora Control", email="cora@medsecure.example", role="user", _module_role="control")
    e = await _entry(db)

    request_der = _endpoint("request_derogation")
    # a read-only account writes nothing, whatever its global account role says
    with pytest.raises(HTTPException) as x:
        await request_der(DerogationCreate(**_der_body(_key(e), project_id=str(PID))), _req(), user=viewer, db=db)
    assert x.value.status_code == 403
    # the object must belong to the record's project, in either direction:
    # no reaching across into another perimeter's entries
    for body in (_der_body(_key(e), project_id=str(elsewhere)),
                 _der_body(f"{elsewhere}:REV-001:{e.id}", project_id=str(PID))):
        with pytest.raises(HTTPException) as x:
            await request_der(DerogationCreate(**body), _req(), user=editor, db=db)
        assert x.value.status_code == 404

    d = await request_der(DerogationCreate(**_der_body(_key(e), project_id=str(PID))), _req(), user=editor, db=db)
    assert d["project_id"] == str(PID)
    decide = _endpoint("decide_derogation")
    for user in (viewer, editor):
        with pytest.raises(HTTPException) as x:
            await decide(d["id"], DecisionBody(approve=True), _req(), user=user, db=db)
        assert x.value.status_code == 403
    # the internal-controls team decides, like the administrator
    decided = await decide(d["id"], DecisionBody(approve=True), _req(), user=control, db=db)
    assert decided["status"] == "approved" and decided["decided_by"] == "Cora Control"
    await db.refresh(e)
    assert e.decision == "derogated"
