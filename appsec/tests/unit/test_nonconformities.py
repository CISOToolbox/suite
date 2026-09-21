"""FEAT-45 — non-conformities and derogations on findings.

The shared mechanics are exercised through AppSec's own models and hook,
against SQLite: request → approve → the finding is derogated; expiry brings
it back to to_fix; a re-detection is silenced; the stats envelope counts
the category on its own and never lets a derogation lift the score."""
import os
import sys
import uuid
from datetime import date, timedelta

import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from starlette.requests import Request  # noqa: E402

from src.models import Application, Base, Derogation, Finding, Measure, Nonconformity  # noqa: E402
from src.nonconformity_common import (DecisionBody, DerogationCreate, NonconformityCreate,  # noqa: E402
                                      NonconformityPatch, QualifyBody, expire_derogations)
from src.routes.nonconformities import FINDING_HOOK, router  # noqa: E402
from src.findings_dedup import upsert_findings  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

APP_ID = uuid.uuid4()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add(Application(id=APP_ID, name="Patient portal"))
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


async def _finding(db, status="to_fix", severity="high"):
    f = Finding(id=uuid.uuid4(), application_id=APP_ID, scanner="trivy", type="cve", severity=severity,
                title="CVE-2026-0001 in lodash", target="package.json", status=status, evidence={},
                dedup_key=f"trivy:{uuid.uuid4()}", cve_id="CVE-2026-0001")
    db.add(f)
    await db.commit()
    return f


def _der_body(fid, **over):
    body = {"subject_type": "finding", "subject_id": str(fid), "title": "Accepted until the framework upgrade",
            "justification": "The dependency is upgraded with the next release; the endpoint is not exposed.",
            "risk_owner": "dev@medsecure.example", "approver": "ciso@medsecure.example",
            "valid_until": (date.today() + timedelta(days=90)).isoformat()}
    body.update(over)
    return body


@pytest.mark.asyncio
async def test_the_hook_names_an_actionable_finding_only(db):
    f = await _finding(db)
    label = await FINDING_HOOK.exists(db, "finding", str(f.id))
    assert label.startswith("CVE-2026-0001")
    assert await FINDING_HOOK.exists(db, "finding", str(uuid.uuid4())) is None
    fixed = await _finding(db, status="fixed")
    with pytest.raises(HTTPException) as e:
        await FINDING_HOOK.exists(db, "finding", str(fixed.id))
    assert e.value.status_code == 409


@pytest.mark.asyncio
async def test_an_approved_derogation_silences_the_finding_until_it_expires(db):
    f = await _finding(db)
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    assert d["status"] == "pending_approval"
    d = await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    assert d["status"] == "approved"
    await db.refresh(f)
    assert f.status == "derogated" and str(f.derogation_id) == d["id"]
    # a re-detection by the scanner is expected: silenced, not reopened
    stats = await upsert_findings(db, APP_ID, [{"scanner": "trivy", "title": f.title, "severity": "high", "type": "cve",
                                                "target": f.target, "dedup_key": f.dedup_key, "evidence": {}}])
    await db.refresh(f)
    assert f.status == "derogated" and stats["silenced"] == 1
    # past its end of validity, the derogation expires and the finding comes back
    der = await db.get(Derogation, uuid.UUID(d["id"]))
    der.valid_until = date.today() - timedelta(days=1)
    await db.commit()
    assert await expire_derogations(db, Derogation, FINDING_HOOK, Nonconformity) == 1
    await db.refresh(f)
    assert f.status == "to_fix" and f.derogation_id is None and "expired" in (f.triage_notes or "")


@pytest.mark.asyncio
async def test_a_second_live_derogation_on_the_same_finding_is_refused(db):
    f = await _finding(db)
    await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    with pytest.raises(HTTPException) as e:
        await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    assert e.value.status_code == 409


@pytest.mark.asyncio
async def test_a_record_concerns_findings_and_its_measures_start_the_remediation(db):
    f1, f2 = await _finding(db), await _finding(db, status="new")
    db.add(Measure(id="MES-A1", title="Upgrade lodash", statut="a_faire", finding_ids=[]))
    await db.commit()
    n = await _endpoint("declare_nonconformity")(
        NonconformityCreate(title="Vulnerable dependency shipped", subjects=[{"type": "finding", "id": str(f1.id)}, {"type": "finding", "id": str(f2.id)}]),
        _req(), user=None, db=db)
    assert [x["id"] for x in n["subjects"]] == [str(f1.id), str(f2.id)] and n["subject_id"] == str(f1.id)
    with pytest.raises(HTTPException) as e:
        await _endpoint("declare_nonconformity")(NonconformityCreate(title="Unknown", subjects=[{"type": "finding", "id": str(uuid.uuid4())}]),
                                                 _req(), user=None, db=db)
    assert e.value.status_code == 404
    await _endpoint("qualify_nonconformity")(n["id"], QualifyBody(), user=None, db=db)
    r = await _endpoint("patch_nonconformity")(n["id"], NonconformityPatch(measure_ids=["MES-A1"]), user=None, db=db)
    assert r["status"] == "in_remediation" and r["measure_ids"] == ["MES-A1"]
    with pytest.raises(HTTPException) as e:
        await _endpoint("patch_nonconformity")(n["id"], NonconformityPatch(measure_ids=["MES-NOPE"]), user=None, db=db)
    assert e.value.status_code == 422


@pytest.mark.asyncio
async def test_stats_envelope_counts_the_category_and_never_greens_the_score(db):
    from src.routes.internal import internal_stats
    f = await _finding(db)                                  # high, to_fix → derogated
    await _finding(db, status="new")                        # high, open
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    await _endpoint("declare_nonconformity")(NonconformityCreate(title="Declared, waiting"), _req(), user=None, db=db)
    n2 = await _endpoint("declare_nonconformity")(NonconformityCreate(title="Declared, then derogated"), _req(), user=None, db=db)
    d2 = await _endpoint("request_derogation")(DerogationCreate(**_der_body(n2["id"], subject_type="nonconformity")), _req(), user=None, db=db)
    await _endpoint("decide_derogation")(d2["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    db.expunge_all()
    sreq = Request({"type": "http", "method": "GET", "path": "/api/internal/stats", "query_string": b"",
                    "headers": [(b"x-service-token", os.environ["SERVICE_TOKEN"].encode())], "client": ("127.0.0.1", 1)})
    stats = await internal_stats(sreq, db)
    assert stats["nonconformities"] == {"derogated": 2, "detected_open": 1, "with_measure": 0, "to_qualify": 1, "open": 0}
    assert stats["high_findings"] == 1                      # the derogated finding leaves the open counters…
    assert stats["posture"]["score"] == 94                  # …but still weighs on the score (two high findings)
