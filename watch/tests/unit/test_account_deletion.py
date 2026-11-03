"""Regression: deleting an account in Pilot must not leave its address with
access in Watch, nor take the person's scopes with it.

- Scope recipients are keyed by email: `delete-user` removes them, or the
  next holder of the address reads those scopes and gets their digests.
  The digest history of the address goes too, archived bodies included.
- `scopes.owner_id` is ON DELETE SET NULL, as in the other modules: the
  scope survives its owner, with its targets and recipients.
- An ownerless scope is managed by Watch administrators; other accounts
  keep the access they had (recipients read, nobody else sees it).
"""
import asyncio
import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

os.environ.setdefault("MODULE_NAME", "watch")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import src.audit_common as audit_mod  # noqa: E402
from src.models import Base, DigestRun, Scope, ScopeRecipient, User, WatchTarget  # noqa: E402
from src.routes import digest as digest_routes, internal, scopes  # noqa: E402

_TOKEN = "test-service-token"
_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _run(coro):
    return asyncio.run(coro)


async def _session():
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})

    @event.listens_for(engine.sync_engine, "connect")
    def _fks(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    tables = [Base.metadata.tables[n] for n in ("users", "scopes", "scope_recipients", "watch_targets", "digest_runs")]
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=tables))
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)()


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    async def _noop(*_a, **_k):
        return None
    monkeypatch.setattr(audit_mod, "log_write", _noop)
    monkeypatch.setattr(scopes, "log_action", _noop)
    monkeypatch.setattr(internal, "SERVICE_TOKEN", _TOKEN)


def _request(email):
    async def _json():
        return {"email": email}
    return SimpleNamespace(headers={"X-Service-Token": _TOKEN}, json=_json)


def _actor(row, module_role, role="user"):
    """The request-scoped user the auth dependency hands to a route."""
    u = SimpleNamespace(id=row.id, email=row.email, name="", role=role, ai_enabled="false")
    u._module_role = module_role
    return u


async def _world(db):
    """Alice owns a scope addressed to Bob and Carol; Bob owns one addressed
    to Alice."""
    now = datetime.now(timezone.utc)
    alice = User(id=uuid.uuid4(), email="alice@medsecure.example")
    bob = User(id=uuid.uuid4(), email="bob@medsecure.example")
    ada = User(id=uuid.uuid4(), email="ada@medsecure.example")
    db.add_all([alice, bob, ada])
    await db.flush()
    s_alice = Scope(id=uuid.uuid4(), owner_id=alice.id, name="MedSecure SOC", created_at=now, updated_at=now)
    s_bob = Scope(id=uuid.uuid4(), owner_id=bob.id, name="MedSecure Cloud", created_at=now, updated_at=now)
    db.add_all([s_alice, s_bob])
    await db.flush()
    db.add_all([
        ScopeRecipient(scope_id=s_alice.id, email="bob@medsecure.example", added_at=now),
        ScopeRecipient(scope_id=s_alice.id, email="carol@medsecure.example", added_at=now),
        ScopeRecipient(scope_id=s_bob.id, email="alice@medsecure.example", added_at=now),
        WatchTarget(id=uuid.uuid4(), scope_id=s_alice.id, kind="keyword", value="medsecure",
                    created_at=now, updated_at=now),
    ])
    await db.commit()
    # Plain values: the rows are expired once delete-user has run.
    return SimpleNamespace(
        alice=SimpleNamespace(id=alice.id, email=alice.email),
        bob=SimpleNamespace(id=bob.id, email=bob.email),
        ada=SimpleNamespace(id=ada.id, email=ada.email),
        s_alice=SimpleNamespace(id=s_alice.id), s_bob=SimpleNamespace(id=s_bob.id))


async def _delete_alice(db):
    w = await _world(db)
    resp = await internal.delete_user(_request("Alice@MedSecure.example"), db)
    db.expire_all()
    return w, resp


async def _recipients(db):
    rows = (await db.execute(select(ScopeRecipient.scope_id, ScopeRecipient.email))).all()
    return {(sid, email) for sid, email in rows}


# ── delete-user ─────────────────────────────────────────────────────

def test_delete_user_removes_the_recipient_rows_of_the_address():
    async def go():
        db = await _session()
        w, resp = await _delete_alice(db)
        assert resp == {"ok": True, "deleted": True}
        assert (w.s_bob.id, "alice@medsecure.example") not in await _recipients(db)
    _run(go())


def test_delete_user_removes_recipients_of_an_address_without_account():
    async def go():
        db = await _session()
        await _world(db)
        resp = await internal.delete_user(_request("carol@medsecure.example"), db)
        assert resp["deleted"] is True
        assert all(email != "carol@medsecure.example" for _, email in await _recipients(db))
    _run(go())


def test_digest_history_of_the_address_is_not_handed_to_its_next_holder():
    async def go():
        db = await _session()
        w = await _world(db)
        db.add(DigestRun(user_email="alice@medsecure.example", scope_id=w.s_bob.id, kind="vuln",
                         calendar_date="2026-11-02", status="sent", body_html="<p>MedSecure digest</p>"))
        await db.commit()
        await internal.delete_user(_request("alice@medsecure.example"), db)
        # The address is given to someone else, who gets a Watch role.
        newcomer = User(id=uuid.uuid4(), email="alice@medsecure.example")
        db.add(newcomer)
        await db.commit()
        runs = await digest_routes.list_runs(_actor(newcomer, "editor"), db)
        assert runs == []
        left = (await db.execute(select(DigestRun))).scalars().all()
        assert left == []
    _run(go())


def test_owned_scope_survives_its_owner_with_targets_and_recipients():
    async def go():
        db = await _session()
        w, _ = await _delete_alice(db)
        scope = await db.get(Scope, w.s_alice.id)
        assert scope is not None
        assert scope.owner_id is None
        assert (w.s_alice.id, "bob@medsecure.example") in await _recipients(db)
        targets = (await db.execute(select(WatchTarget).where(WatchTarget.scope_id == w.s_alice.id))).scalars().all()
        assert len(targets) == 1
    _run(go())


# ── Ownerless scope: managed by administrators ──────────────────────

def test_admin_lists_and_manages_an_ownerless_scope():
    async def go():
        db = await _session()
        w, _ = await _delete_alice(db)
        admin = _actor(w.ada, "admin")
        listed = {s.id: s for s in await scopes.list_scopes(admin, db)}
        assert w.s_alice.id in listed
        assert listed[w.s_alice.id].is_owner is True
        assert listed[w.s_alice.id].owner_id is None
        out = await scopes.update_scope(w.s_alice.id, scopes.ScopeUpdate(name="MedSecure SOC (kept)"), None, admin, db)
        assert out.name == "MedSecure SOC (kept)"
    _run(go())


def test_suite_admin_manages_an_ownerless_scope():
    async def go():
        db = await _session()
        w, _ = await _delete_alice(db)
        admin = _actor(w.ada, "viewer", role="admin")
        listed = {s.id: s for s in await scopes.list_scopes(admin, db)}
        assert listed[w.s_alice.id].is_owner is True
    _run(go())


def test_editor_neither_sees_nor_edits_an_ownerless_scope():
    async def go():
        db = await _session()
        w, _ = await _delete_alice(db)
        editor = _actor(w.ada, "editor")
        assert w.s_alice.id not in {s.id for s in await scopes.list_scopes(editor, db)}
        with pytest.raises(HTTPException) as exc:
            await scopes.update_scope(w.s_alice.id, scopes.ScopeUpdate(name="x"), None, editor, db)
        assert exc.value.status_code == 403
    _run(go())


def test_recipient_still_reads_an_ownerless_scope_without_managing_it():
    async def go():
        db = await _session()
        w, _ = await _delete_alice(db)
        bob = _actor(w.bob, "editor")
        listed = {s.id: s for s in await scopes.list_scopes(bob, db)}
        assert listed[w.s_alice.id].is_owner is False
        with pytest.raises(HTTPException) as exc:
            await scopes.delete_scope(w.s_alice.id, None, bob, db)
        assert exc.value.status_code == 403
    _run(go())


# ── Schema ──────────────────────────────────────────────────────────

def test_owner_fk_is_set_null_and_migrated():
    fk = next(iter(Scope.__table__.c.owner_id.foreign_keys))
    assert fk.ondelete == "SET NULL"
    assert Scope.__table__.c.owner_id.nullable is True
    mig = (_ROOT / "alembic" / "versions" / "015_scope_owner_set_null.py").read_text()
    assert 'down_revision = "014_alerts_kev_listed_at"' in mig
    assert 'ondelete="SET NULL"' in mig and "nullable=True" in mig
