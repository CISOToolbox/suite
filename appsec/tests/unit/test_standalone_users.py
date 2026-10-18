"""FEAT-58 — standalone accounts and roles, without Pilot.

The shared auth (``src/auth_common.py``) and user router
(``src/users_admin_common.py``), against SQLite, with real session cookies.
Locks:
  - sign-in: the first account is the admin, every other one awaits approval
    and is refused with the approval message; a former ``user`` row counts as
    pending; a disabled account is refused;
  - the role is read from the table on every request: an admin's change —
    approval, the intermediate tier of the module's ladder, a demotion, a
    disabled account, back to pending — applies to the next request of an
    open session, and the session never writes its own role back;
  - a session whose account was removed, or whose id does not match, is 401;
  - the router: admin only, the module's ladder plus pending/disabled, the
    last active admin cannot be demoted nor disabled, 409 in the suite;
  - the suite path is unchanged: the role comes from Pilot's session and is
    mirrored into the table;
  - the module's key opens one local account, its admin, whatever address is
    typed; it never takes over a provider account; that account's role is
    fixed; the shared token rules with an identity provider.
"""
from __future__ import annotations

import os
import sys

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/appsec_test")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from fastapi import HTTPException  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import auth_common, users_admin_common  # noqa: E402
from src.database import get_db  # noqa: E402
from src.models import User  # noqa: E402

_APPSEC_ROLES = ["viewer", "triager", "admin"]


@pytest_asyncio.fixture
async def sessions():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(User.__table__.create)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def setup(monkeypatch, sessions):
    def mode(value: str):
        monkeypatch.setattr(auth_common, "AUTH_MODE", value)
        monkeypatch.setattr(users_admin_common, "AUTH_MODE", value)
    mode("standalone")
    monkeypatch.setattr(auth_common, "AUTH_TOKEN", "a-standalone-token")
    monkeypatch.setattr(auth_common, "MODULE_NAME", "appsec")
    # Whatever environment the module was first imported with in this run:
    # the session key, audience and issuer of a standalone AppSec.
    secret = "test-secret-that-is-long-enough-32ch"
    audience = auth_common.module_audience("appsec")
    monkeypatch.setattr(auth_common, "JWT_SECRET", secret)
    monkeypatch.setattr(auth_common, "TOKEN_AUDIENCE", audience)
    monkeypatch.setattr(auth_common, "TOKEN_ISSUER", "ciso-appsec")
    monkeypatch.setattr(auth_common, "JWT_KEY", auth_common.derive_jwt_key(secret, audience))

    async def _db():
        async with sessions() as s:
            yield s

    app = FastAPI()
    app.include_router(users_admin_common.router)

    @app.get("/probe/read")
    async def read(user=Depends(auth_common.get_current_user)):
        return {"role": auth_common.get_module_role(user)}

    @app.post("/probe/triage")
    async def triage(user=Depends(auth_common.get_current_user)):
        auth_common.require_min_role(user, "triager", _APPSEC_ROLES)
        return {"ok": True}

    app.dependency_overrides[get_db] = _db

    async def sign_in(email: str):
        async with sessions() as db:
            # Several accounts: an identity provider's (the key opens one only).
            user = await auth_common.standalone_sign_in(db, email, provider="google", provider_id="g-" + email)
        return auth_common.create_jwt(str(user.id), user.email, user.role,
                                      auth_common.standalone_permissions(user))

    def client(token: str | None = None):
        cookies = {auth_common.COOKIE_NAME: token} if token else {}
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", cookies=cookies)

    async def row(email: str) -> User:
        async with sessions() as db:
            return (await db.execute(select(User).where(User.email == email))).scalar_one()

    async def set_role(email: str, role: str):
        async with sessions() as db:
            u = (await db.execute(select(User).where(User.email == email))).scalar_one()
            u.role = role
            await db.commit()

    return {"sign_in": sign_in, "client": client, "row": row, "set_role": set_role, "mode": mode,
            "sessions": sessions}


async def _approve(s, admin_token, email, role):
    target = await s["row"](email)
    async with s["client"](admin_token) as c:
        return await c.put(f"/api/users/{target.id}", json={"role": role})


@pytest.mark.asyncio
async def test_first_account_is_admin_the_next_awaits_approval(setup):
    s = setup
    await s["sign_in"]("ciso@medsecure.example")
    assert (await s["row"]("ciso@medsecure.example")).role == "admin"
    with pytest.raises(HTTPException) as exc:
        await s["sign_in"]("analyst@medsecure.example")
    assert exc.value.status_code == 403 and "awaiting administrator approval" in exc.value.detail
    assert (await s["row"]("analyst@medsecure.example")).role == "pending"


@pytest.mark.asyncio
async def test_a_former_user_row_counts_as_pending(setup):
    s = setup
    await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("legacy@medsecure.example")
    await s["set_role"]("legacy@medsecure.example", "user")  # what token-only modules used to store
    with pytest.raises(HTTPException) as exc:
        await s["sign_in"]("legacy@medsecure.example")
    assert exc.value.status_code == 403 and "approval" in exc.value.detail


@pytest.mark.asyncio
async def test_approval_grants_the_intermediate_tier(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    r = await _approve(s, admin, "analyst@medsecure.example", "triager")
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "active"
    analyst = await s["sign_in"]("analyst@medsecure.example")
    async with s["client"](analyst) as c:
        assert (await c.get("/probe/read")).json() == {"role": "triager"}
        assert (await c.post("/probe/triage")).status_code == 200


@pytest.mark.asyncio
async def test_a_role_change_applies_to_the_open_session(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    await _approve(s, admin, "analyst@medsecure.example", "triager")
    analyst = await s["sign_in"]("analyst@medsecure.example")  # its session says triager
    await _approve(s, admin, "analyst@medsecure.example", "viewer")
    async with s["client"](analyst) as c:
        assert (await c.get("/probe/read")).json() == {"role": "viewer"}
        assert (await c.post("/probe/triage")).status_code == 403
    # The session never wrote its own role back.
    assert (await s["row"]("analyst@medsecure.example")).role == "viewer"


@pytest.mark.asyncio
@pytest.mark.parametrize("state, detail", [("disabled", "disabled"), ("pending", "approval")])
async def test_disabling_or_unapproving_ends_the_open_session(setup, state, detail):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    await _approve(s, admin, "analyst@medsecure.example", "triager")
    analyst = await s["sign_in"]("analyst@medsecure.example")
    assert (await _approve(s, admin, "analyst@medsecure.example", state)).json()["state"] == state
    async with s["client"](analyst) as c:
        r = await c.get("/probe/read")
    assert r.status_code == 401 and detail in r.json()["detail"]
    with pytest.raises(HTTPException) as exc:
        await s["sign_in"]("analyst@medsecure.example")
    assert exc.value.status_code == 403 and detail in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_a_session_never_recreates_an_account(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    stranger = auth_common.create_jwt("00000000-0000-0000-0000-000000000001", "ciso@medsecure.example",
                                      "admin", {"appsec": "admin"})  # right email, wrong id
    ghost = auth_common.create_jwt("00000000-0000-0000-0000-000000000002", "ghost@medsecure.example",
                                   "admin", {"appsec": "admin"})
    for token in (stranger, ghost):
        async with s["client"](token) as c:
            assert (await c.get("/probe/read")).status_code == 401
    async with s["client"](admin) as c:
        assert (await c.get("/api/users")).json()["users"].__len__() == 1


@pytest.mark.asyncio
async def test_the_last_admin_cannot_be_demoted_nor_disabled(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    for role in ("viewer", "disabled", "pending"):
        r = await _approve(s, admin, "ciso@medsecure.example", role)
        assert r.status_code == 409, (role, r.text)
    with pytest.raises(HTTPException):
        await s["sign_in"]("deputy@medsecure.example")
    await _approve(s, admin, "deputy@medsecure.example", "admin")
    assert (await _approve(s, admin, "ciso@medsecure.example", "viewer")).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["user", "editor", "superadmin", ""])
async def test_only_the_module_ladder_pending_and_disabled_are_granted(setup, role):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    r = await _approve(s, admin, "analyst@medsecure.example", role)
    assert r.status_code == 400
    assert (await s["row"]("analyst@medsecure.example")).role == "pending"


@pytest.mark.asyncio
async def test_list_reports_states_and_the_ladder(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    async with s["client"](admin) as c:
        body = (await c.get("/api/users")).json()
    assert body["roles"] == ["viewer", "triager", "admin"] and body["managed"] is False
    assert [(u["email"], u["state"]) for u in body["users"]] == [
        ("ciso@medsecure.example", "active"), ("analyst@medsecure.example", "pending")]


@pytest.mark.asyncio
async def test_ai_access_can_be_granted(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    target = await s["row"]("ciso@medsecure.example")
    async with s["client"](admin) as c:
        r = await c.put(f"/api/users/{target.id}", json={"ai_enabled": True})
    assert r.json()["ai_enabled"] is True
    assert (await s["row"]("ciso@medsecure.example")).ai_enabled == "true"


@pytest.mark.asyncio
async def test_a_non_admin_cannot_manage_users(setup):
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    await _approve(s, admin, "analyst@medsecure.example", "triager")
    analyst = await s["sign_in"]("analyst@medsecure.example")
    target = await s["row"]("analyst@medsecure.example")
    async with s["client"](analyst) as c:
        assert (await c.get("/api/users")).status_code == 403
        assert (await c.put(f"/api/users/{target.id}", json={"role": "admin"})).status_code == 403


@pytest.mark.asyncio
async def test_suite_mode_users_are_pilots(setup):
    s = setup
    s["mode"]("pilot")
    token = auth_common.create_jwt("00000000-0000-0000-0000-00000000000a", "ciso@medsecure.example",
                                   "user", {"appsec": "triager"})
    async with s["client"](token) as c:
        # Role from Pilot's session, mirrored into the table.
        assert (await c.get("/probe/read")).json() == {"role": "triager"}
    assert (await s["row"]("ciso@medsecure.example")).role == "user"
    admin = auth_common.create_jwt("00000000-0000-0000-0000-00000000000b", "boss@medsecure.example",
                                   "admin", {"appsec": "admin"})
    target = await s["row"]("ciso@medsecure.example")
    async with s["client"](admin) as c:
        listing = (await c.get("/api/users")).json()
        r = await c.put(f"/api/users/{target.id}", json={"role": "viewer"})
    assert listing["managed"] is True and listing["users"] == []
    assert r.status_code == 409


@pytest.mark.parametrize("detail, code", [
    ("Account created and awaiting administrator approval", "awaiting_approval"),
    ("Account disabled", "account_disabled"),
    ("Email domain not allowed", "domain_not_allowed"),
    ("anything else", "access_denied"),
])
def test_a_refused_oauth_sign_in_goes_back_to_the_login_page(detail, code):
    from src.auth_routes_common import _refused_sign_in
    r = _refused_sign_in(HTTPException(status_code=403, detail=detail))
    assert r.status_code in (302, 303, 307) and r.headers["location"] == f"/login.html?error={code}"


@pytest.fixture
def token_login(setup, monkeypatch):
    """The module's own /auth routes, standalone, with or without an identity provider."""
    from src import auth_routes_common as routes_auth
    monkeypatch.setattr(routes_auth, "AUTH_MODE", "standalone")
    monkeypatch.setattr(routes_auth, "AUTH_TOKEN", "a-standalone-token")

    def make(provider: bool):
        monkeypatch.setattr(routes_auth, "GOOGLE_CLIENT_ID", "client-id" if provider else "")
        monkeypatch.setattr(routes_auth, "GOOGLE_CLIENT_SECRET", "client-secret" if provider else "")
        app = FastAPI()
        app.include_router(routes_auth.router)

        async def _db():
            async with setup["sessions"]() as s:
                yield s
        app.dependency_overrides[get_db] = _db
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    return make


async def _token(c, email):
    return await c.post("/auth/login/token", json={"token": "a-standalone-token", "email": email})


async def _google(setup, email):
    """A sign-in through the identity provider, as the OAuth callback does it."""
    async with setup["sessions"]() as db:
        return await auth_common.standalone_sign_in(db, email, provider="google", provider_id="g-" + email)


async def _token_open(c) -> bool:
    return (await c.get("/auth/providers")).json()["token"]


@pytest.mark.asyncio
async def test_set_up_with_the_token_then_the_admin_signs_in_through_the_provider(token_login, setup):
    """The documented path: bootstrap with the token, approve the provider
    account as admin, and the token closes once that admin has signed in."""
    async with token_login(provider=True) as c:
        assert (await _token(c, "admin@local")).status_code == 200      # set up with the token
        admin = auth_common.create_jwt(str((await setup["row"]("admin@local")).id), "admin@local",
                                       "admin", {"appsec": "admin"})
        with pytest.raises(HTTPException):
            await _google(setup, "ciso@medsecure.example")              # pending: does not close it
        assert await _token_open(c)
        await _approve(setup, admin, "ciso@medsecure.example", "admin")
        # Created through the provider: approved as admin, it closes the token.
        assert not await _token_open(c)
        await _google(setup, "ciso@medsecure.example")                   # and can sign in
        for email in ("admin@local", "ciso@medsecure.example", "analyst@medsecure.example", ""):
            r = await _token(c, email)
            assert r.status_code == 403 and "identity provider" in r.json()["detail"], email


@pytest.mark.asyncio
async def test_an_account_created_with_the_token_closes_it_once_it_signs_in_through_the_provider(token_login, setup):
    async with token_login(provider=True) as c:
        assert (await _token(c, "ciso@medsecure.example")).status_code == 200   # own address
        await _google(setup, "ciso@medsecure.example")
        assert (await setup["row"]("ciso@medsecure.example")).provider == "google"
        assert not await _token_open(c)


@pytest.mark.asyncio
async def test_the_token_opens_again_when_no_admin_signs_in_through_the_provider(token_login, setup):
    async with token_login(provider=True) as c:
        assert (await _token(c, "admin@local")).status_code == 200
        admin = auth_common.create_jwt(str((await setup["row"]("admin@local")).id), "admin@local",
                                       "admin", {"appsec": "admin"})
        with pytest.raises(HTTPException):
            await _google(setup, "ciso@medsecure.example")
        await _approve(setup, admin, "ciso@medsecure.example", "admin")
        await _google(setup, "ciso@medsecure.example")
        assert not await _token_open(c)
        await _approve(setup, admin, "ciso@medsecure.example", "disabled")
        assert await _token_open(c)   # the way back in


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["pilot", "", None])
async def test_an_admin_from_elsewhere_does_not_close_the_token(token_login, setup, provider):
    """An admin row that came from Pilot (suite then standalone, or a sync)
    has never signed in through this module's provider."""
    async with token_login(provider=True) as c:
        async with setup["sessions"]() as db:
            db.add(User(email="boss@medsecure.example", name="boss", provider=provider,
                        provider_id="", role="admin"))
            await db.commit()
        assert await _token_open(c)


@pytest.mark.asyncio
async def test_the_last_admin_guard_locks_the_admin_rows(setup):
    """Two demotions at the same time: the count runs on locked rows, so the
    second waits for the first and sees what it left. SQLite cannot run the
    race; what update_user really executes is checked instead."""
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("deputy@medsecure.example")
    await _approve(s, admin, "deputy@medsecure.example", "admin")
    seen = []

    def capture(state):
        if state.is_select:
            seen.append(state.statement)
    event.listen(Session, "do_orm_execute", capture)
    try:
        assert (await _approve(s, admin, "ciso@medsecure.example", "viewer")).status_code == 200
    finally:
        event.remove(Session, "do_orm_execute", capture)
    locked = [st for st in seen if getattr(st, "_for_update_arg", None) is not None]
    assert locked, "the admin count runs without a row lock"
    assert any("users.role" in str(st.whereclause) for st in locked)


@pytest.mark.asyncio
async def test_a_role_change_says_what_changed_to_the_journal(setup, monkeypatch):
    """Through the module's own write-journal middleware."""
    from src import audit_common, database
    s = setup
    admin = await s["sign_in"]("ciso@medsecure.example")
    with pytest.raises(HTTPException):
        await s["sign_in"]("analyst@medsecure.example")
    target = await s["row"]("analyst@medsecure.example")
    entries = []

    async def log_write(db, user, request, action, **kw):
        entries.append((action, kw.get("details")))
    monkeypatch.setattr(audit_common, "log_write", log_write)
    monkeypatch.setattr(database, "async_session", s["sessions"])
    app = FastAPI()
    app.include_router(users_admin_common.router)
    audit_common.install_write_journal_middleware(app)

    async def _db():
        async with s["sessions"]() as db:
            yield db
    app.dependency_overrides[get_db] = _db
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t",
                                 cookies={auth_common.COOKIE_NAME: admin}) as c:
        assert (await c.put(f"/api/users/{target.id}", json={"role": "triager"})).status_code == 200
    assert entries and entries[-1][1] == {"role": "pending -> triager"}, entries


# ── The key is the module's local account ─────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("provider", [False, True])
async def test_the_key_always_opens_the_same_local_account(token_login, setup, provider):
    async with token_login(provider=provider) as c:
        assert (await c.get("/auth/providers")).json()["token_setup"] is True
        first = await _token(c, "ciso@medsecure.example")
        assert first.status_code == 200 and first.json()["role"] == "admin"
        assert (await c.get("/auth/providers")).json()["token_setup"] is False
        for email in ("someone@else.example", "", "ciso@medsecure.example"):
            r = await _token(c, email)
            assert r.status_code == 200, (email, r.text)
            assert r.json()["email"] == "ciso@medsecure.example"
    async with setup["sessions"]() as db:
        assert (await db.execute(select(User))).scalars().all().__len__() == 1


@pytest.mark.asyncio
async def test_the_local_account_ignores_the_domain_filter(token_login, monkeypatch):
    from src import auth_routes_common as routes_auth
    monkeypatch.setattr(routes_auth, "_ALLOWED_EMAIL_DOMAINS", {"medsecure.example"})
    async with token_login(provider=False) as c:
        r = await _token(c, "")
    assert r.status_code == 200 and r.json()["email"] == "admin@local"


@pytest.mark.asyncio
async def test_the_key_never_takes_over_a_provider_account(token_login, setup):
    async with token_login(provider=True) as c:
        await _google(setup, "ciso@medsecure.example")          # first account: admin, closes the key
        async with setup["sessions"]() as db:                    # the provider admin is disabled
            u = (await db.execute(select(User).where(User.email == "ciso@medsecure.example"))).scalar_one()
            u.role = "disabled"
            await db.commit()
        assert (await c.get("/auth/providers")).json()["token"] is True   # the way back in
        r = await _token(c, "ciso@medsecure.example")                    # not the provider account
        assert r.status_code == 409, r.text
        r = await _token(c, "")                                          # a local account instead
        assert r.status_code == 200 and r.json()["role"] == "admin" and r.json()["email"] == "admin@local"


@pytest.mark.asyncio
async def test_the_local_account_role_is_fixed(token_login, setup):
    async with token_login(provider=True) as c:
        local = await _token(c, "admin@local")
        admin = local.cookies.get(auth_common.COOKIE_NAME)
        with pytest.raises(HTTPException):
            await _google(setup, "deputy@medsecure.example")
        await _approve(setup, admin, "deputy@medsecure.example", "admin")
        deputy_session = auth_common.create_jwt(str((await setup["row"]("deputy@medsecure.example")).id),
                                                "deputy@medsecure.example", "admin", {"appsec": "admin"})
        for role in ("viewer", "disabled", "pending"):
            r = await _approve(setup, deputy_session, "admin@local", role)
            assert r.status_code == 409, (role, r.text)
        async with setup["client"](admin) as c2:
            body = (await c2.get("/api/users")).json()
        local_row = next(u for u in body["users"] if u["email"] == "admin@local")
        assert local_row["local"] is True and body["identity_provider"] is True


@pytest.mark.asyncio
async def test_without_a_provider_the_users_section_knows_it(token_login, setup):
    async with token_login(provider=False) as c:
        admin = (await _token(c, "ciso@medsecure.example")).cookies.get(auth_common.COOKIE_NAME)
    async with setup["client"](admin) as c2:
        body = (await c2.get("/api/users")).json()
    assert body["identity_provider"] is False and [u["local"] for u in body["users"]] == [True]


@pytest.mark.asyncio
async def test_only_the_key_s_account_is_fixed(token_login, setup):
    """Other admins created with the key (an older instance) stay ordinary
    accounts: an admin can demote or disable them."""
    async with token_login(provider=False) as c:
        local = (await _token(c, "first@medsecure.example")).cookies.get(auth_common.COOKIE_NAME)
    async with setup["sessions"]() as db:
        db.add(User(email="second@medsecure.example", name="second", provider="token",
                    provider_id="token", role="admin"))
        await db.commit()
    async with setup["client"](local) as c2:
        body = (await c2.get("/api/users")).json()
    assert {u["email"]: u["local"] for u in body["users"]} == {
        "first@medsecure.example": True, "second@medsecure.example": False}
    assert (await _approve(setup, local, "second@medsecure.example", "disabled")).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["disabled", "pending", "viewer"])
async def test_the_key_never_brings_back_another_account(token_login, setup, role):
    """No local account (its owner moved to a provider): the key names a new
    one, but never revives or promotes an existing account."""
    async with token_login(provider=False) as c:
        async with setup["sessions"]() as db:
            db.add(User(email="boss@medsecure.example", name="boss", provider="pilot",
                        provider_id="", role="admin"))
            db.add(User(email="bob@medsecure.example", name="bob", provider="token",
                        provider_id="token", role=role))
            await db.commit()
        r = await _token(c, "bob@medsecure.example")
        assert r.status_code == 409, r.text
        assert (await setup["row"]("bob@medsecure.example")).role == role
        r = await _token(c, "   ")
        assert r.status_code == 200 and r.json()["email"] == "admin@local"


@pytest.mark.asyncio
@pytest.mark.parametrize("idp, verified, ok", [
    ("google", True, True), ("google", "true", True), ("google", False, False), ("google", None, False),
    ("oidc", True, True), ("oidc", "true", True), ("oidc", False, False), ("oidc", "false", False),
    ("oidc", None, True),  # an OIDC server that does not say is trusted for its own users
])
async def test_an_unverified_provider_address_is_refused(setup, monkeypatch, idp, verified, ok):
    from src import auth_routes_common as routes_auth
    info = {"email": "ciso@medsecure.example", "sub": "s-1", "name": "ciso"}
    if verified is not None:
        info["email_verified"] = verified

    class Resp:
        is_success = True
        def json(self):
            return info

    class Client:
        token = None
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch_token(self, *a, **k): return {"access_token": "x"}
        async def get(self, *a, **k): return Resp()

    async def endpoints():
        return {"token_endpoint": "https://idp.example/token", "userinfo_endpoint": "https://idp.example/userinfo"}
    monkeypatch.setattr(routes_auth, "AsyncOAuth2Client", Client)
    monkeypatch.setattr(routes_auth, "_verify_oauth_state", lambda request: None)
    monkeypatch.setattr(routes_auth, "_get_oidc_endpoints", endpoints)
    monkeypatch.setattr(routes_auth, "AUTH_MODE", "standalone")
    for name in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.setattr(routes_auth, name, "x")
    monkeypatch.setattr(routes_auth, "OIDC_ISSUER", "https://idp.example")
    app = FastAPI()
    app.include_router(routes_auth.router)

    async def _db():
        async with setup["sessions"]() as db:
            yield db
    app.dependency_overrides[get_db] = _db
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/auth/callback/{idp}?code=c&state=s")
    assert r.status_code in (302, 303, 307), r.text
    if ok:
        assert "error=" not in r.headers["location"], r.headers
    else:
        assert r.headers["location"].endswith("error=email_not_verified")


@pytest.mark.asyncio
async def test_the_account_creation_lock_comes_before_the_lookup(token_login, monkeypatch):
    """Two first sign-ins at the same time: the lock is taken before the
    module looks for an existing account (SQLite cannot run the race)."""
    order = []
    real_lock, real_local = auth_common._serialize_account_creation, auth_common.local_account

    async def lock(db):
        order.append("lock")
        await real_lock(db)

    async def local(db):
        order.append("lookup")
        return await real_local(db)
    monkeypatch.setattr(auth_common, "_serialize_account_creation", lock)
    monkeypatch.setattr(auth_common, "local_account", local)
    async with token_login(provider=False) as c:
        assert (await _token(c, "ciso@medsecure.example")).status_code == 200
    assert "lock" in order and order[order.index("lock"):][:2] == ["lock", "lookup"], order


@pytest.mark.asyncio
async def test_the_account_creation_lock_is_a_postgresql_advisory_lock():
    from types import SimpleNamespace as NS
    sent = []

    class Db:
        bind = NS(dialect=NS(name="postgresql"))
        async def execute(self, stmt):
            sent.append(str(stmt))
    await auth_common._serialize_account_creation(Db())
    assert sent and "pg_advisory_xact_lock" in sent[0]
