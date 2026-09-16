"""FEAT-45 — the consolidated register: read live from the modules,
writes relayed with the Pilot user as actor, digest reminders on derogations."""
import json
import os
import sys
from datetime import date, timedelta

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.models import Base, ModuleRegistry  # noqa: E402
from src.routes import nonconformities as reg  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb", "false", "true")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add_all([
            ModuleRegistry(id="surface", name="Surface", internal_url="http://surface:8000", external_url="/surface/", status="active"),
            ModuleRegistry(id="compliance", name="Compliance", internal_url="http://compliance:8000", external_url="/compliance/", status="active"),
            ModuleRegistry(id="risk", name="Risk", internal_url="http://risk:8000", external_url="/risk/", status="active"),
            ModuleRegistry(id="watch", name="Watch", internal_url="http://watch:8000", external_url="/watch/", status="inactive"),
        ])
        await session.commit()
        yield session
    await engine.dispose()


def _fake_modules(seen: list, down: set | None = None):
    """A transport standing for the modules: Surface and Compliance keep a
    register, Risk does not (404), every call must carry the token, and the
    hosts in `down` time out or fail."""
    down = down or set()
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url), request.headers.get("x-service-token")))
        host = request.url.host
        path = request.url.path
        if host in down:
            if down == {"timeout"} or host == "timeout":
                raise httpx.ConnectTimeout("timed out")
            return httpx.Response(500, text="boom")
        if request.headers.get("x-service-token") != os.environ["SERVICE_TOKEN"]:
            return httpx.Response(403, json={"detail": "Invalid service token"})
        if host == "risk":
            return httpx.Response(404)
        if path.endswith("/internal/nonconformities") and request.method == "GET":
            items = [{"id": f"nc-{host}", "reference": "NC-2026-001", "title": f"gap in {host}", "status": "open",
                      "severity": "high", "created_at": "2026-09-10T00:00:00+00:00", "treatment": "none"}]
            return httpx.Response(200, json={"items": items, "total": 1})
        if path.endswith("/internal/nonconformities") and request.method == "POST":
            body = json.loads(request.content)
            return httpx.Response(201, json={"id": "nc-new", "reference": "NC-2026-002", "status": "to_qualify",
                                             "declared_by": body.get("actor"), "title": body.get("title")})
        if path.endswith("/internal/derogations"):
            wanted = request.url.params.get("status")
            rows = [{"id": f"der-{host}", "reference": "DER-2026-001", "title": f"accepted in {host}",
                     "status": "approved", "risk_owner": "ops@medsecure.example", "approver": "ciso@medsecure.example",
                     "valid_until": (date.today() + timedelta(days=5)).isoformat(),
                     "created_at": "2026-09-11T00:00:00+00:00"},
                    {"id": f"der-{host}-old", "reference": "DER-2026-000", "title": f"expired in {host}",
                     "status": "expired", "risk_owner": "ops@medsecure.example", "approver": "ciso@medsecure.example",
                     "valid_until": (date.today() - timedelta(days=3)).isoformat(),
                     "created_at": "2026-06-11T00:00:00+00:00"}]
            items = [r for r in rows if not wanted or r["status"] == wanted]
            return httpx.Response(200, json={"items": items, "total": len(items)})
        if "/internal/derogations/" in path and path.endswith("/decision"):
            body = json.loads(request.content)
            if path.split("/")[-2] == "der-gone":
                return httpx.Response(409, json={"detail": "the subject is no longer open: nothing to derogate"})
            return httpx.Response(200, json={"id": path.split("/")[-2], "status": "approved" if body["approve"] else "rejected",
                                             "decided_by": body.get("actor")})
        if path.endswith("/internal/nonconformities-settings"):
            if request.method == "PUT":
                return httpx.Response(200, json={"max_derogation_days": json.loads(request.content)["max_derogation_days"]})
            return httpx.Response(200, json={"max_derogation_days": 180 if host == "surface" else 365})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


@pytest.fixture
def modules(monkeypatch):
    seen: list = []
    monkeypatch.setattr(reg, "_TRANSPORT", _fake_modules(seen))
    return seen


@pytest.mark.asyncio
async def test_register_reads_every_module_live_and_stamps_the_owner(db, modules):
    out = await reg.list_nonconformities(user=None, db=db)
    assert out["total"] == 2 and out["errors"] == {}
    mods = sorted(it["module"] for it in out["items"])
    assert mods == ["compliance", "surface"]
    surf = [it for it in out["items"] if it["module"] == "surface"][0]
    assert surf["module_url"] == "/surface/?nc=nc-surface#nonconformities" and surf["module_name"] == "Surface"
    # the inactive module is never called, the one without a register is silently absent
    hosts = {url.split("//")[1].split(":")[0] for _, url, _ in modules}
    assert "watch" not in hosts and "risk" in hosts
    assert all(tok == os.environ["SERVICE_TOKEN"] for _, _, tok in modules)

    ders = await reg.list_derogations(module="compliance", user=None, db=db)
    assert ders["total"] == 2 and all(it["module"] == "compliance" for it in ders["items"])


@pytest.mark.asyncio
async def test_decision_and_declaration_are_relayed_with_the_pilot_user(db, modules):
    class U:  # the Pilot user, as the auth layer hands it over
        name = "Sam Approver"
        email = "sam@medsecure.example"
        role = "admin"
    out = await reg.decide_derogation("surface", "der-surface", reg.DecisionBody(approve=True, note="ok"), user=U(), db=db)
    assert out["status"] == "approved" and out["decided_by"] == "Sam Approver"
    relayed = [c for c in modules if c[0] == "POST" and c[1].endswith("/decision")]
    assert relayed and relayed[0][1].startswith("http://surface:8000/api/internal/derogations/der-surface")

    # the module's own refusal comes back unchanged
    with pytest.raises(HTTPException) as e:
        await reg.decide_derogation("surface", "der-gone", reg.DecisionBody(approve=True), user=U(), db=db)
    assert e.value.status_code == 409 and "no longer open" in e.value.detail

    # unknown or inactive module: 404 before any call
    with pytest.raises(HTTPException) as e:
        await reg.decide_derogation("watch", "der-x", reg.DecisionBody(approve=True), user=U(), db=db)
    assert e.value.status_code == 404

    nc = await reg.declare_nonconformity(reg.DeclarationBody(module="compliance", title="Declared from the console",
                                                             severity="medium"), user=U(), db=db)
    assert nc["declared_by"] == "Sam Approver" and nc["module"] == "compliance"
    assert nc["module_url"] == "/compliance/?nc=nc-new#nonconformities"


@pytest.mark.asyncio
async def test_a_failing_module_is_reported_not_fatal(db, monkeypatch):
    seen: list = []
    monkeypatch.setattr(reg, "_TRANSPORT", _fake_modules(seen, down={"compliance"}))
    out = await reg.list_nonconformities(user=None, db=db)
    assert out["total"] == 1 and out["items"][0]["module"] == "surface"
    assert out["errors"] == {"compliance": "HTTP 500"}

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")
    monkeypatch.setattr(reg, "_TRANSPORT", httpx.MockTransport(timeout_handler))
    out = await reg.list_derogations(user=None, db=db)
    assert out["total"] == 0 and set(out["errors"]) == {"surface", "compliance", "risk"}

    # an active module without register: 404 from the relay, not a 502
    monkeypatch.setattr(reg, "_TRANSPORT", _fake_modules(seen))
    class U:
        name = "Sam"; email = "sam@medsecure.example"; role = "admin"
    with pytest.raises(HTTPException) as e:
        await reg.declare_nonconformity(reg.DeclarationBody(module="risk", title="no register here"), user=U(), db=db)
    assert e.value.status_code == 404 and "risk" in e.value.detail


@pytest.mark.asyncio
async def test_settings_are_read_per_module_and_written_to_one(db, modules):
    out = await reg.list_settings(user=None, db=db)
    assert [(i["module"], i["max_derogation_days"]) for i in out["items"]] == [("compliance", 365), ("surface", 180)]
    res = await reg.put_settings("surface", reg.SettingsBody(max_derogation_days=90), user=None, db=db)
    assert res == {"max_derogation_days": 90}


@pytest.mark.asyncio
async def test_digest_reminds_the_risk_owner_of_an_expiring_derogation(db, modules):
    from src.deadline_digest import collect_derogation_items, _item_url
    from src.models import NotificationPrefs, User
    import uuid
    user = User(id=uuid.uuid4(), email="ops@medsecure.example", name="Ops", role="user")
    prefs = NotificationPrefs(user_id=user.id, enabled=True, upcoming_days=14, include_overdue=True,
                              scope="mine", modules=[], lang="en")
    items = await collect_derogation_items(db, prefs, user, today=date.today())
    ders = [i for i in items if i.get("type") == "derogation"]
    # one approved derogation ending in 5 days and one expired 3 days ago, per module
    assert sorted((i["kind"], i["days"]) for i in ders) == [("overdue", 3), ("overdue", 3), ("upcoming", 5), ("upcoming", 5)]
    assert _item_url(ders[0], {"surface": "/surface/", "compliance": "/compliance/"}, "/") == "/" + ders[0]["module"] + "/?der=" + ders[0]["source_id"] + "#nonconformities"

    # someone else gets nothing under scope "mine"
    other = User(id=uuid.uuid4(), email="nobody@medsecure.example", name="Nobody", role="user")
    assert await collect_derogation_items(db, prefs, other, today=date.today()) == []
