"""Account deletion leaves nothing the next holder of the address inherits.

- The Pilot row goes only once every module has confirmed. Until then the
  account stays listed as pending deletion: it cannot sign in, modules see it
  inactive, the address cannot open a new account, and calling the deletion
  again retries the modules. `skipped` (no internal_url) settles a module,
  `unsupported` (image without the route) does not.
- The directory entry is kept for history, inactive, detached from the
  address: a new account with that address gets a fresh entry.
- The digest subscription goes at once.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from src import auth as pilot_core_auth
from src.models import ModuleRegistry, NotificationPrefs, Personnel, User
from src.routes import auth as pilot_auth
from src.routes import users as users_routes

pytestmark = pytest.mark.asyncio

_SVC = {"X-Service-Token": "test-service-token"}
_EMAIL = "alice@medsecure.example"


async def _user(db, email=_EMAIL, role="user", name="Alice Martin"):
    u = User(email=email, name=name, provider="oidc", provider_id=email, role=role,
             modules=["risk"], permissions={"risk": "editor"})
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


def _modules_answer(monkeypatch, report):
    async def _fake(email, db):
        return dict(report)
    monkeypatch.setattr(users_routes, "_delete_user_in_modules", _fake)


async def _reload(db, user_id):
    db.expire_all()
    return await db.get(User, user_id)


# ── Unfinished deletion ─────────────────────────────────────────────

async def test_unconfirmed_module_keeps_the_account_pending(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"risk": "deleted", "watch": "error: timeout"})
    r = await client.delete(f"/api/users/{u.id}")
    assert r.status_code == 200
    body = r.json()
    assert body["pending"] is True and body["failed"] == ["watch"]
    row = await _reload(db, u.id)
    assert row is not None
    assert row.deletion_requested_at is not None
    assert row.deletion_report == {"risk": "deleted", "watch": "error: timeout"}


async def test_pending_deletion_is_listed_with_its_report(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    await client.delete(f"/api/users/{u.id}")
    listed = {x["email"]: x for x in (await client.get("/api/users")).json()}
    assert listed[_EMAIL]["deletion_requested_at"] is not None
    assert listed[_EMAIL]["deletion_report"] == {"watch": "HTTP 503"}


async def test_retry_deletes_the_account_once_every_module_confirms(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"risk": "deleted", "watch": "HTTP 503"})
    await client.delete(f"/api/users/{u.id}")
    _modules_answer(monkeypatch, {"risk": "absent", "watch": "deleted"})
    r = await client.delete(f"/api/users/{u.id}")
    assert r.json()["pending"] is False and r.json()["failed"] == []
    assert await _reload(db, u.id) is None


async def test_unsupported_module_keeps_the_account_pending(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"risk": "deleted", "watch": "unsupported"})
    r = await client.delete(f"/api/users/{u.id}")
    assert r.json()["failed"] == ["watch"]
    assert await _reload(db, u.id) is not None


async def test_module_without_internal_url_settles(client, db):
    db.add(ModuleRegistry(id="risk", name="Risk", internal_url="", external_url="/risk/"))
    await db.commit()
    u = await _user(db)
    r = await client.delete(f"/api/users/{u.id}")
    assert r.json()["modules"] == {"risk": "skipped"}
    assert r.json()["failed"] == []
    assert await _reload(db, u.id) is None


async def test_pending_deletion_cannot_sign_in(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    await client.delete(f"/api/users/{u.id}")
    db.expire_all()  # the route ran in its own session
    resp = await pilot_auth._finish_sign_in(
        SimpleNamespace(cookies={}), db, email=_EMAIL.upper(), name="Someone Else",
        picture="", provider="oidc", provider_id="new")
    assert resp.headers["location"] == "/login.html?error=account_deleting"
    assert "set-cookie" not in resp.headers
    rows = (await db.execute(select(User).where(User.email == _EMAIL))).scalars().all()
    assert len(rows) == 1 and rows[0].name == "Alice Martin"


async def test_pending_deletion_session_is_refused(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    uid = u.id
    await client.delete(f"/api/users/{uid}")
    db.expire_all()  # the route ran in its own session
    monkeypatch.setattr(pilot_core_auth, "auth_enabled", lambda: True)
    monkeypatch.setattr(pilot_core_auth, "decode_jwt", lambda token: {"sub": uid})
    request = SimpleNamespace(cookies={pilot_core_auth.COOKIE_NAME: "session"})
    with pytest.raises(HTTPException) as exc:
        await pilot_core_auth._resolve_user(request, db)
    assert exc.value.status_code == 401


async def test_pending_deletion_is_inactive_for_the_modules(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    await client.delete(f"/api/users/{u.id}")
    r = await client.get("/api/internal/users/status",
                         params={"email": _EMAIL, "module": "risk"}, headers=_SVC)
    assert r.json()["active"] is False


async def test_pending_deletion_role_cannot_be_changed(client, db, monkeypatch):
    u = await _user(db)
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    await client.delete(f"/api/users/{u.id}")
    r = await client.put(f"/api/users/{u.id}", json={"role": "admin"})
    assert r.status_code == 409


async def test_admin_pending_deletion_does_not_count_as_remaining_admin(client, db, monkeypatch):
    leaving = await _user(db, email="leaving@medsecure.example", role="admin")
    last = await _user(db, email="ada@medsecure.example", role="admin")
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    await client.delete(f"/api/users/{leaving.id}")
    r = await client.put(f"/api/users/{last.id}", json={"role": "user"})
    assert r.status_code == 409


async def test_digest_subscription_goes_with_the_first_attempt(client, db, monkeypatch):
    u = await _user(db)
    db.add(NotificationPrefs(user_id=u.id, enabled=True))
    await db.commit()
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    uid = u.id
    await client.delete(f"/api/users/{uid}")
    db.expire_all()
    assert await db.get(NotificationPrefs, uid) is None


# ── Directory entry ─────────────────────────────────────────────────

async def _entry(db, email):
    return (await db.execute(select(Personnel).where(Personnel.email == email))).scalar_one_or_none()


async def test_directory_entry_is_kept_inactive_and_detached(client, db, monkeypatch):
    u = await _user(db)
    db.add(Personnel(email=_EMAIL, prenom="Alice", nom="Martin", fonction="RSSI",
                     manager_email="ceo@medsecure.example", statut="actif"))
    await db.commit()
    _modules_answer(monkeypatch, {"risk": "deleted"})
    await client.delete(f"/api/users/{u.id}")
    db.expire_all()
    assert await _entry(db, _EMAIL) is None
    kept = (await db.execute(select(Personnel))).scalars().all()
    assert len(kept) == 1
    assert kept[0].statut == "inactif"
    assert kept[0].fonction == "RSSI"
    assert kept[0].email.startswith(_EMAIL + ".deleted-") and kept[0].email.endswith(".invalid")


async def test_new_account_with_the_address_gets_a_fresh_entry(client, db, monkeypatch):
    await _user(db, email="admin@medsecure.example", role="admin")
    u = await _user(db)
    db.add(Personnel(email=_EMAIL, prenom="Alice", nom="Martin", fonction="RSSI", statut="actif"))
    await db.commit()
    _modules_answer(monkeypatch, {"risk": "deleted"})
    await client.delete(f"/api/users/{u.id}")
    newcomer = await pilot_auth._upsert_user(db, email=_EMAIL, name="Bob Durand",
                                             picture="", provider="oidc", provider_id="bob")
    assert newcomer.role == "pending"
    r = await client.put(f"/api/users/{newcomer.id}", json={"role": "user"})
    assert r.status_code == 200
    db.expire_all()
    fresh = await _entry(db, _EMAIL)
    assert (fresh.prenom, fresh.nom, fresh.fonction, fresh.statut) == ("Bob", "Durand", "", "actif")


async def test_access_fed_entry_is_left_to_access(client, db, monkeypatch):
    u = await _user(db)
    db.add(Personnel(email=_EMAIL, prenom="Alice", nom="Martin", statut="actif", sync_source="access"))
    await db.commit()
    _modules_answer(monkeypatch, {"risk": "deleted"})
    await client.delete(f"/api/users/{u.id}")
    db.expire_all()
    entry = await _entry(db, _EMAIL)
    assert entry is not None and entry.statut == "actif"


# ── No mail to an account pending deletion ──────────────────────────
# A module may still see the account active for a few minutes (status cache)
# and write its preferences again after the first attempt dropped them.

async def _pending(client, db, monkeypatch):
    u = await _user(db)
    uid = u.id
    _modules_answer(monkeypatch, {"watch": "HTTP 503"})
    await client.delete(f"/api/users/{uid}")
    db.expire_all()
    return uid


async def test_module_cannot_resubscribe_a_pending_account(client, db, monkeypatch):
    uid = await _pending(client, db, monkeypatch)
    r = await client.put("/api/internal/notification-prefs", headers=_SVC,
                         json={"email": _EMAIL, "prefs": {"enabled": True}})
    assert r.status_code == 404
    db.expire_all()
    assert await db.get(NotificationPrefs, uid) is None


async def test_module_cannot_send_a_test_digest_to_a_pending_account(client, db, monkeypatch):
    await _pending(client, db, monkeypatch)
    for path in ("/api/internal/notification-test", "/api/internal/notification-test-all"):
        r = await client.post(path, headers=_SVC, json={"email": _EMAIL})
        assert r.status_code == 404, path


async def test_weekly_digest_skips_a_pending_account(client, db, monkeypatch):
    from datetime import datetime, timezone

    from src import deadline_digest

    uid = await _pending(client, db, monkeypatch)
    now = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)  # a Monday, after the send hour
    db.add(NotificationPrefs(user_id=uid, enabled=True, day_of_week=now.weekday()))
    await db.commit()
    sent = []

    async def _send(db_, user, prefs, **_kw):
        sent.append(user.email)
        return "sent"
    monkeypatch.setattr(deadline_digest, "send_digest_for_user", _send)
    await deadline_digest.tick_digests(db, now=now)
    assert sent == []


async def test_pending_account_is_no_alert_subscriber(client, db, monkeypatch):
    uid = await _pending(client, db, monkeypatch)
    db.add(NotificationPrefs(user_id=uid, enabled=True,
                             module_prefs={"surface": {"alert_enabled": True}}))
    await db.commit()
    r = await client.post("/api/internal/notification-subscribers", headers=_SVC,
                          json={"module": "surface"})
    assert r.json()["subscribers"] == []


# ── Concurrent retries ──────────────────────────────────────────────

@pytest.mark.parametrize("this_attempt", [{"risk": "deleted"}, {"risk": "HTTP 503"}],
                         ids=["confirmed", "unconfirmed"])
async def test_retry_finding_the_row_already_gone_succeeds(client, db, monkeypatch, this_attempt):
    u = await _user(db)
    uid = u.id

    async def _other_retry_won(email, db_):
        # Another retry completed while this one waited on the modules.
        await db.execute(User.__table__.delete().where(User.id == uid))
        await db.commit()
        return dict(this_attempt)
    monkeypatch.setattr(users_routes, "_delete_user_in_modules", _other_retry_won)
    r = await client.delete(f"/api/users/{uid}")
    assert r.status_code == 200
    # The account is gone: the answer is a settled deletion either way.
    assert r.json()["pending"] is False and r.json()["failed"] == []
    assert all(v in ("deleted", "absent", "skipped") for v in r.json()["modules"].values())
    db.expire_all()
    assert await db.get(User, uid) is None
