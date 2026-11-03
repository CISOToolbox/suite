"""Sign-in gates of Pilot, and the account state it serves to the modules.

- `/api/internal/users/status?module=<m>` returns the account's current role
  in that module (`module_role`): a module lowers its session to it, so a
  demotion applies without waiting for the 24 h session to expire.
- `ALLOWED_EMAIL_DOMAINS`, when set, refuses an address outside it before any
  account is created, as the standalone modules do.
- A pending account is only a sign-in attempt: it enters the directory when an
  admin approves it, not at sign-in.
- The id_token of the OIDC fallback is checked against `OIDC_ISSUER` when the
  discovery document carries no issuer, instead of not being checked at all.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from src.models import Personnel, User
from src.routes import auth as pilot_auth

pytestmark = pytest.mark.asyncio

_SVC = {"X-Service-Token": "test-service-token"}


async def _user(db, email, role, permissions=None):
    u = User(email=email, name="Alice Martin", provider="oidc", provider_id=email,
             role=role, modules=list(permissions or {}), permissions=permissions or {})
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


async def _personnel(db, email):
    return (await db.execute(select(Personnel).where(Personnel.email == email))).scalar_one_or_none()


# ── /users/status ───────────────────────────────────────────────────

async def test_status_returns_the_role_of_the_asked_module(client, db):
    await _user(db, "alice@medsecure.example", "user", {"risk": "viewer", "vendor": "manager"})
    r = await client.get("/api/internal/users/status",
                         params={"email": "alice@medsecure.example", "module": "risk"}, headers=_SVC)
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["role"] == "user"
    assert body["module_role"] == "viewer"


async def test_status_module_role_is_empty_without_an_entry(client, db):
    await _user(db, "alice@medsecure.example", "user", {"vendor": "manager"})
    r = await client.get("/api/internal/users/status",
                         params={"email": "alice@medsecure.example", "module": "risk"}, headers=_SVC)
    assert r.json()["module_role"] == ""


async def test_status_without_module_returns_no_module_role(client, db):
    await _user(db, "alice@medsecure.example", "user", {"risk": "editor"})
    r = await client.get("/api/internal/users/status",
                         params={"email": "alice@medsecure.example"}, headers=_SVC)
    assert r.json()["module_role"] == ""


async def test_status_of_an_unknown_account(client):
    r = await client.get("/api/internal/users/status",
                         params={"email": "nobody@medsecure.example", "module": "risk"}, headers=_SVC)
    assert r.json() == {"exists": False, "active": False, "role": "", "modules": [], "module_role": ""}


# ── ALLOWED_EMAIL_DOMAINS ───────────────────────────────────────────

async def test_address_outside_the_allowed_domains_gets_no_account(db, monkeypatch):
    monkeypatch.setattr(pilot_auth, "_ALLOWED_EMAIL_DOMAINS", ("medsecure.example",))
    with pytest.raises(pilot_auth.HTTPException) as exc:
        await pilot_auth._upsert_user(db, email="mallory@evil.example", name="Mallory",
                                      picture="", provider="oidc", provider_id="m")
    assert exc.value.status_code == 403
    assert (await db.execute(select(User))).scalars().all() == []
    assert await _personnel(db, "mallory@evil.example") is None


async def test_subdomain_of_an_allowed_domain_is_refused(db, monkeypatch):
    monkeypatch.setattr(pilot_auth, "_ALLOWED_EMAIL_DOMAINS", ("medsecure.example",))
    with pytest.raises(pilot_auth.HTTPException):
        await pilot_auth._upsert_user(db, email="eve@evil.medsecure.example", name="Eve",
                                      picture="", provider="oidc", provider_id="e")


async def test_address_in_an_allowed_domain_signs_in(db, monkeypatch):
    monkeypatch.setattr(pilot_auth, "_ALLOWED_EMAIL_DOMAINS", ("medsecure.example",))
    user = await pilot_auth._upsert_user(db, email="Alice@MedSecure.example", name="Alice Martin",
                                         picture="", provider="oidc", provider_id="a")
    assert user.email == "alice@medsecure.example"


async def test_refused_domain_goes_back_to_the_sign_in_page(db, monkeypatch):
    monkeypatch.setattr(pilot_auth, "_ALLOWED_EMAIL_DOMAINS", ("medsecure.example",))
    resp = await pilot_auth._finish_sign_in(
        SimpleNamespace(cookies={}), db, email="mallory@evil.example", name="Mallory",
        picture="", provider="oidc", provider_id="m")
    assert resp.headers["location"] == "/login.html?error=domain_not_allowed"
    assert "set-cookie" not in resp.headers


# ── Directory entry only for an approved account ────────────────────

async def test_first_account_admin_enters_the_directory(db):
    user = await pilot_auth._upsert_user(db, email="admin@medsecure.example", name="Ada Admin",
                                         picture="", provider="oidc", provider_id="ad")
    assert user.role == "admin"
    assert await _personnel(db, "admin@medsecure.example") is not None


async def test_pending_account_does_not_enter_the_directory(db):
    await _user(db, "admin@medsecure.example", "admin")
    user = await pilot_auth._upsert_user(db, email="newcomer@medsecure.example", name="New Comer",
                                         picture="", provider="oidc", provider_id="n")
    assert user.role == "pending"
    assert await _personnel(db, "newcomer@medsecure.example") is None
    # Signing in again while still pending changes nothing.
    await pilot_auth._upsert_user(db, email="newcomer@medsecure.example", name="New Comer",
                                  picture="", provider="oidc", provider_id="n")
    assert await _personnel(db, "newcomer@medsecure.example") is None


async def test_approval_enters_the_account_in_the_directory(client, db):
    await _user(db, "admin@medsecure.example", "admin")
    pending = await _user(db, "newcomer@medsecure.example", "pending")
    r = await client.put(f"/api/users/{pending.id}", json={"role": "user"})
    assert r.status_code == 200
    entry = await _personnel(db, "newcomer@medsecure.example")
    assert entry is not None
    assert (entry.prenom, entry.nom, entry.statut) == ("Alice", "Martin", "actif")


async def test_approved_account_signing_in_enters_the_directory(db):
    await _user(db, "admin@medsecure.example", "admin")
    await _user(db, "bob@medsecure.example", "user")
    await pilot_auth._upsert_user(db, email="bob@medsecure.example", name="Bob Durand",
                                  picture="", provider="oidc", provider_id="b")
    assert await _personnel(db, "bob@medsecure.example") is not None


async def test_other_role_changes_create_no_entry(client, db):
    await _user(db, "admin@medsecure.example", "admin")
    viewer = await _user(db, "carol@medsecure.example", "viewer")
    r = await client.put(f"/api/users/{viewer.id}", json={"role": "user"})
    assert r.status_code == 200
    assert await _personnel(db, "carol@medsecure.example") is None


# ── OIDC issuer fallback ────────────────────────────────────────────

async def test_id_token_is_checked_against_the_configured_issuer(db, monkeypatch):
    seen = {}

    class _Client:
        def __init__(self, **_):
            self.token = None

        async def fetch_token(self, *_, **__):
            return {"id_token": "header.payload.sig"}

    async def _endpoints():
        # No `issuer`, no userinfo: the id_token fallback is the identity.
        return {"token_endpoint": "https://idp.medsecure.example/token",
                "jwks_uri": "https://idp.medsecure.example/jwks"}

    async def _verify(id_token, jwks_url, audience, issuer=None):
        seen["issuer"] = issuer
        raise ValueError("stop here")

    monkeypatch.setattr(pilot_auth, "OIDC_ISSUER", "https://idp.medsecure.example")
    monkeypatch.setattr(pilot_auth, "_oidc_configured", lambda: True)
    monkeypatch.setattr(pilot_auth, "_get_oidc_endpoints", _endpoints)
    monkeypatch.setattr(pilot_auth, "_verify_oauth_state", lambda request: None)
    monkeypatch.setattr(pilot_auth, "AsyncOAuth2Client", _Client)
    monkeypatch.setattr(pilot_auth, "_verify_id_token_jwks", _verify)

    request = SimpleNamespace(cookies={}, url="https://pilot.medsecure.example/auth/callback/oidc?code=x")
    resp = await pilot_auth.callback_oidc(request, db)
    assert resp.headers["location"] == "/login.html?error=token_verify_failed"
    assert seen["issuer"] == "https://idp.medsecure.example"
