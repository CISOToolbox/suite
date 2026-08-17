from __future__ import annotations

import os
import secrets
import logging
from datetime import datetime, timezone

from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import (
    COOKIE_NAME,
    VALID_MODULES,
    auth_enabled,
    create_jwt,
    create_module_jwt,
    get_current_user_permissive,
    module_cookie_name,
    module_cookie_path,
)
from src.database import get_db
from src.models import Personnel, User
from src.schemas import UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

APP_URL = os.getenv("APP_URL", "http://localhost:8090")

ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "")
ENTRA_CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "")
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID", "common")

ENTRA_AUTH_URL = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/authorize"
ENTRA_TOKEN_URL = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/token"

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "")
OIDC_LABEL = os.getenv("OIDC_LABEL", "SSO")

SCOPES = "openid profile email"

_oidc_endpoints: dict | None = None


def _entra_configured() -> bool:
    """Entra is usable only with an EXPLICIT tenant id.

    The default was "common", which builds an issuer of
    .../common/v2.0 — a value no real token ever carries, since Entra stamps
    the tenant GUID. Verification therefore failed for everyone, and the
    obvious way out of a login that "just doesn't work" is to switch
    verify_iss off, which is precisely the check that keeps another tenant's
    token from being accepted here. Refuse the multi-tenant placeholder
    instead of failing later for a reason nobody can read.
    """
    if not (ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET):
        return False
    if ENTRA_TENANT_ID in ("", "common", "organizations", "consumers"):
        logger.warning(
            "Entra ID is configured but ENTRA_TENANT_ID is %r: set it to your "
            "tenant GUID. Issuer verification cannot succeed against a "
            "multi-tenant placeholder, so the provider is disabled.",
            ENTRA_TENANT_ID or "(empty)",
        )
        return False
    return True


def _google_configured() -> bool:
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _oidc_configured() -> bool:
    return bool(OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_ISSUER)


async def _get_oidc_endpoints() -> dict:
    global _oidc_endpoints
    if _oidc_endpoints:
        return _oidc_endpoints
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.get(OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration", timeout=10)
        resp.raise_for_status()
        _oidc_endpoints = resp.json()
    return _oidc_endpoints


@router.get("/providers")
async def get_providers():
    return {
        "auth_enabled": auth_enabled(),
        "entra": _entra_configured(),
        "google": _google_configured(),
        "oidc": _oidc_configured(),
        "oidc_label": OIDC_LABEL if _oidc_configured() else None,
    }



# ── OIDC nonce + PKCE ────────────────────────────────────────────
#
# `state` was the only per-flow secret: it stops login CSRF, but says nothing
# about the token that comes back. Two gaps followed, both required by OIDC
# Core §3.1.2.1 / RFC 7636:
#
#  * no `nonce` — an id_token obtained elsewhere for the same client could be
#    replayed into our callback; the nonce binds a token to the exact browser
#    flow that asked for it;
#  * no PKCE — an authorization code intercepted before the exchange (a leaked
#    redirect, a shared device, a malicious extension) is redeemable on its
#    own; with PKCE it is worthless without the verifier, which never leaves
#    this server.
#
# Both live in short-lived httpOnly cookies next to oauth_state, so they share
# its lifetime and its clean-up.

def _new_pkce() -> tuple[str, str]:
    """Return `(code_verifier, code_challenge)` for the S256 method."""
    import hashlib
    from base64 import urlsafe_b64encode

    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _begin_oauth(response, redirect_after: str, state: str,
                 verifier: str, nonce: str = "") -> None:
    """Attach the per-flow cookies to the redirect that starts the flow."""
    common = dict(httponly=True, samesite="lax", max_age=600,
                  secure=_cookie_secure())
    response.set_cookie("oauth_state", state, **common)
    response.set_cookie("oauth_redirect", redirect_after, **common)
    response.set_cookie("oauth_pkce", verifier, **common)
    if nonce:
        response.set_cookie("oauth_nonce", nonce, **common)


def _verify_nonce(request: Request, claims: dict) -> None:
    """The id_token must echo the nonce we minted for THIS browser flow.

    Compared with compare_digest and required on both sides: an id_token
    arriving without one is exactly the replay case this guards against.
    """
    expected = request.cookies.get("oauth_nonce", "")
    returned = str(claims.get("nonce") or "")
    if not expected or not returned or not secrets.compare_digest(returned, expected):
        raise HTTPException(status_code=400, detail="Invalid OAuth nonce")


def _clear_oauth_cookies(response):
    for name in ("oauth_state", "oauth_redirect", "oauth_pkce", "oauth_nonce"):
        response.delete_cookie(name)
    return response


@router.get("/login/entra")
async def login_entra(request: Request):
    if not _entra_configured():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    redirect_uri = APP_URL + "/auth/callback/entra"
    redirect_after = _sanitize_redirect(request.query_params.get("redirect", "/"))
    client = AsyncOAuth2Client(client_id=ENTRA_CLIENT_ID, client_secret=ENTRA_CLIENT_SECRET, redirect_uri=redirect_uri, scope=SCOPES)
    verifier, challenge = _new_pkce()
    nonce = secrets.token_urlsafe(32)
    uri, state = client.create_authorization_url(
        ENTRA_AUTH_URL, code_challenge=challenge,
        code_challenge_method="S256", nonce=nonce,
    )
    response = RedirectResponse(url=uri)
    _begin_oauth(response, redirect_after, state, verifier, nonce)
    return response


def _verify_oauth_state(request: Request) -> None:
    """CSRF guard: the `state` the IdP echoes back MUST equal the one we
    set at login (the oauth_state cookie). Without it an attacker can feed
    a victim their own authorization code and silently log the victim into
    the attacker's account (login CSRF)."""
    expected = request.cookies.get("oauth_state")
    returned = request.query_params.get("state")
    # compare_digest, not !=: exploitability is nil here (the state is a
    # short-lived random value and an attacker cannot replay guesses
    # against the same one), but every other secret comparison in the
    # suite is constant-time, and an inconsistent habit is what ends up
    # copied into a place where it does matter.
    if not expected or not returned or not secrets.compare_digest(returned, expected):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")


@router.get("/callback/entra")
async def callback_entra(request: Request, db: AsyncSession = Depends(get_db)):
    if not _entra_configured():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    redirect_uri = APP_URL + "/auth/callback/entra"
    _verify_oauth_state(request)
    client = AsyncOAuth2Client(client_id=ENTRA_CLIENT_ID, client_secret=ENTRA_CLIENT_SECRET, redirect_uri=redirect_uri)
    try:
        token = await client.fetch_token(
            ENTRA_TOKEN_URL, authorization_response=str(request.url),
            code_verifier=request.cookies.get("oauth_pkce", ""),
        )
    except Exception:
        return RedirectResponse(url="/login.html?error=auth_failed")
    id_token = token.get("id_token", "")
    if not id_token:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    # Verify id_token signature against Entra JWKS
    jwks_url = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys"
    issuer = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"
    try:
        claims = await _verify_id_token_jwks(id_token, jwks_url, audience=ENTRA_CLIENT_ID, issuer=issuer)
    except Exception:
        return RedirectResponse(url="/login.html?error=token_verify_failed")
    # Signature and audience are not enough: they hold for any id_token minted
    # for this client. The nonce is what ties this one to this browser flow.
    _verify_nonce(request, claims)
    email = claims.get("email") or claims.get("preferred_username", "")
    name = claims.get("name", "")
    provider_id = claims.get("oid") or claims.get("sub", "")
    if not email:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    user = await _upsert_user(db, email=email, name=name, picture="", provider="entra", provider_id=provider_id)
    redirect_after = request.cookies.get("oauth_redirect", "/")
    return _login_response(user, redirect_after)


@router.get("/login/google")
async def login_google(request: Request):
    if not _google_configured():
        raise HTTPException(status_code=503, detail="Google OAuth not configured")
    redirect_uri = APP_URL + "/auth/callback/google"
    redirect_after = _sanitize_redirect(request.query_params.get("redirect", "/"))
    client = AsyncOAuth2Client(client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, redirect_uri=redirect_uri, scope=SCOPES)
    # Google is consumed through userinfo, not the id_token, so there is
    # no nonce to bind — PKCE still protects the code exchange.
    verifier, challenge = _new_pkce()
    uri, state = client.create_authorization_url(
        GOOGLE_AUTH_URL, code_challenge=challenge, code_challenge_method="S256",
    )
    response = RedirectResponse(url=uri)
    _begin_oauth(response, redirect_after, state, verifier)
    return response


@router.get("/callback/google")
async def callback_google(request: Request, db: AsyncSession = Depends(get_db)):
    if not _google_configured():
        raise HTTPException(status_code=503, detail="Google OAuth not configured")
    redirect_uri = APP_URL + "/auth/callback/google"
    _verify_oauth_state(request)
    client = AsyncOAuth2Client(client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, redirect_uri=redirect_uri)
    try:
        token = await client.fetch_token(
            GOOGLE_TOKEN_URL, authorization_response=str(request.url),
            code_verifier=request.cookies.get("oauth_pkce", ""),
        )
    except Exception:
        return RedirectResponse(url="/login.html?error=auth_failed")
    client.token = token
    resp = await client.get(GOOGLE_USERINFO_URL)
    if not resp.is_success:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    userinfo = resp.json()
    user = await _upsert_user(db, email=userinfo.get("email", ""), name=userinfo.get("name", ""), picture=userinfo.get("picture", ""), provider="google", provider_id=userinfo.get("sub", ""))
    redirect_after = request.cookies.get("oauth_redirect", "/")
    return _login_response(user, redirect_after)


@router.get("/login/oidc")
async def login_oidc(request: Request):
    if not _oidc_configured():
        raise HTTPException(status_code=503, detail="OIDC not configured")
    endpoints = await _get_oidc_endpoints()
    redirect_uri = APP_URL + "/auth/callback/oidc"
    redirect_after = _sanitize_redirect(request.query_params.get("redirect", "/"))
    client = AsyncOAuth2Client(client_id=OIDC_CLIENT_ID, client_secret=OIDC_CLIENT_SECRET, redirect_uri=redirect_uri, scope=SCOPES)
    verifier, challenge = _new_pkce()
    nonce = secrets.token_urlsafe(32)
    uri, state = client.create_authorization_url(
        endpoints["authorization_endpoint"], code_challenge=challenge,
        code_challenge_method="S256", nonce=nonce,
    )
    response = RedirectResponse(url=uri)
    _begin_oauth(response, redirect_after, state, verifier, nonce)
    return response


@router.get("/callback/oidc")
async def callback_oidc(request: Request, db: AsyncSession = Depends(get_db)):
    if not _oidc_configured():
        raise HTTPException(status_code=503, detail="OIDC not configured")
    endpoints = await _get_oidc_endpoints()
    redirect_uri = APP_URL + "/auth/callback/oidc"
    _verify_oauth_state(request)
    client = AsyncOAuth2Client(client_id=OIDC_CLIENT_ID, client_secret=OIDC_CLIENT_SECRET, redirect_uri=redirect_uri)
    try:
        token = await client.fetch_token(
            endpoints["token_endpoint"], authorization_response=str(request.url),
            code_verifier=request.cookies.get("oauth_pkce", ""),
        )
    except Exception:
        return RedirectResponse(url="/login.html?error=auth_failed")
    client.token = token
    userinfo = None
    # Prefer a fresh userinfo call (server-side), fall back to the id_token if not available.
    userinfo_url = endpoints.get("userinfo_endpoint")
    if userinfo_url:
        resp = await client.get(userinfo_url)
        if resp.is_success:
            userinfo = resp.json()
    if userinfo is None:
        # Fallback: verify the id_token against the provider's JWKS
        id_token = token.get("id_token", "")
        jwks_url = endpoints.get("jwks_uri")
        if not id_token or not jwks_url:
            return RedirectResponse(url="/login.html?error=userinfo_failed")
        try:
            userinfo = await _verify_id_token_jwks(
                id_token, jwks_url,
                audience=OIDC_CLIENT_ID,
                issuer=endpoints.get("issuer"),
            )
        except Exception:
            return RedirectResponse(url="/login.html?error=token_verify_failed")
        # Only on this branch: here the id_token IS the identity assertion, so
        # it must be bound to this flow. The userinfo branch above fetches the
        # identity server-side with a token we just obtained — nothing to replay.
        _verify_nonce(request, userinfo)
    email = userinfo.get("email", "")
    if not email:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    user = await _upsert_user(db, email=email, name=userinfo.get("name") or userinfo.get("preferred_username", ""), picture=userinfo.get("picture", ""), provider="oidc", provider_id=userinfo.get("sub", ""))
    redirect_after = request.cookies.get("oauth_redirect", "/")
    return _login_response(user, redirect_after)


@router.post("/logout")
async def logout():
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(COOKIE_NAME, samesite="lax")
    _clear_module_cookies(response)
    return response


@router.get("/logout")
async def logout_get(request: Request):
    """GET variant used by modules that redirect to /auth/logout to
    clear the shared pilot_token cookie. Clears the cookie and sends
    the user back to the login page.

    CSRF hardening (AUTH-06): a GET that mutates state can be forced by
    any third-party page via a top-level navigation (SameSite=Lax does
    not block those). Browsers label such navigations with
    Sec-Fetch-Site: cross-site — in that case redirect WITHOUT touching
    the session cookie. Same-origin module redirects (same-origin/
    same-site), direct address-bar visits ("none") and legacy browsers
    that omit the header keep working unchanged."""
    response = RedirectResponse(url="/login.html", status_code=302)
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return response
    response.delete_cookie(COOKIE_NAME, samesite="lax", path="/",
                           httponly=True, secure=_cookie_secure())
    _clear_module_cookies(response)
    return response


# Synthetic identity served by /auth/me when AUTH_MODE=none: no user row
# exists and every route is admin by contract, so the SPA bootstrap must get
# a 200 with an admin-shaped payload instead of a 401 (AUTH-02b).
_NO_AUTH_ME = {
    "id": "00000000-0000-0000-0000-000000000000",
    "email": "admin@local",
    "name": "Admin (auth disabled)",
    "picture": None,
    "provider": "none",
    "role": "admin",
    "modules": sorted(VALID_MODULES),
    "permissions": {},
    "ai_enabled": "true",
    "created_at": None,
    "last_login": None,
}


@router.get("/me", response_model=UserResponse)
async def me(response: Response, user: User = Depends(get_current_user_permissive)):
    if user is None:
        # `None` is the "auth disabled" sentinel — a real missing/invalid
        # token already raised 401 inside the dependency.
        return JSONResponse(_NO_AUTH_ME)
    # Refresh the per-module SSO cookies on the way (AUTH-01). This is the
    # self-healing point of the flow: a module whose cookie is missing or
    # expired returns 401, the SPA sends the browser to /login.html, and
    # login.js calls this endpoint — which re-mints the module cookies and
    # bounces straight back. Without it, a still-valid Pilot session with a
    # stale module cookie would loop between the module and the login page.
    _set_module_cookies(response, user)
    return user


async def _upsert_user(db: AsyncSession, email: str, name: str, picture: str, provider: str, provider_id: str) -> User:
    # Normalize email to lowercase so identical addresses with different
    # casings (john@x.com vs JOHN@x.com) resolve to a single user account.
    email = (email or "").strip().lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if user:
        user.name = name
        if picture:
            user.picture = picture
        user.last_login = now
    else:
        count_result = await db.execute(select(func.count()).select_from(User))
        user_count = count_result.scalar()
        role = "admin" if user_count == 0 else "pending"
        user = User(
            email=email, name=name, picture=picture, provider=provider,
            provider_id=provider_id, role=role,
            modules=list(VALID_MODULES) if role == "admin" else [],
            last_login=now,
        )
        db.add(user)
    await _ensure_directory_entry(db, email, name)
    await db.commit()
    await db.refresh(user)
    return user


async def _ensure_directory_entry(db: AsyncSession, email: str, name: str) -> None:
    """Auto-provision a personnel directory entry for an OAuth login.

    The directory and the user accounts table are intentionally separate (HR
    directory vs login accounts) but the admin bootstrap and any future OAuth
    user should also appear in the directory so they can be referenced by other
    modules (Access reviewers, project responsables...)."""
    email = (email or "").strip().lower()
    if not email:
        return
    existing = await db.execute(select(Personnel).where(Personnel.email == email))
    if existing.scalar_one_or_none() is not None:
        return
    prenom, nom = "", ""
    if name:
        parts = name.strip().split(" ", 1)
        prenom = parts[0]
        if len(parts) > 1:
            nom = parts[1]
    db.add(Personnel(
        email=email,
        prenom=prenom,
        nom=nom,
        statut="actif",
    ))


def _sanitize_redirect(raw: str | None) -> str:
    """Ensure the post-login redirect is a safe relative path (anti open-redirect)."""
    if not raw:
        return "/"
    # Only accept paths starting with a single "/" and not "//..." (protocol-relative URLs).
    if not raw.startswith("/") or raw.startswith("//") or raw.startswith("/\\"):
        return "/"
    # Reject any absolute URL pattern that slipped in (e.g. "/\\evil.com")
    if "://" in raw:
        return "/"
    return raw


def _cookie_secure() -> bool:
    """Secure cookie flag, fail-secure (AUTH-05).

    Default is Secure. The ONLY opt-out is an APP_URL that explicitly
    declares plain HTTP (local dev behind no TLS). An empty or malformed
    APP_URL must not silently downgrade the session cookie."""
    return not APP_URL.startswith("http://")


async def _verify_id_token_jwks(id_token: str, jwks_url: str, audience: str, issuer: str | None = None) -> dict:
    """Fetch JWKS, verify the id_token signature, and return its claims.

    Uses PyJWKClient (synchronous); wrapped via asyncio.to_thread to avoid
    blocking the event loop.
    """
    import asyncio
    import jwt as jose_jwt
    from jwt import PyJWKClient

    def _work() -> dict:
        client = PyJWKClient(jwks_url)
        signing_key = client.get_signing_key_from_jwt(id_token)
        options = {"verify_signature": True, "verify_aud": bool(audience), "verify_iss": bool(issuer)}
        return jose_jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=audience if audience else None,
            issuer=issuer if issuer else None,
            options=options,
        )

    return await asyncio.to_thread(_work)


def _set_module_cookies(response: Response, user: User) -> None:
    """Drop one SSO cookie per module, each signed with that module's own
    derived key (AUTH-01).

    This is what keeps the suite SSO working now that no module accepts a
    suite-wide token: a single login still opens every module, but each
    module receives a credential only it can verify. Cookies are scoped to
    `/<module>/` — the path nginx proxies to that module — so the browser
    sends exactly one of them per request and never shows Risk's token to
    Surface.

    Minted for every known module, not just `user.modules`: a suite admin
    typically has an empty module list yet is admin everywhere, and a
    token without the matching module role is refused by the module anyway
    (403), so an unused cookie grants nothing.

    Pending users get nothing: their account is not approved yet.
    """
    if (user.role or "") == "pending":
        return
    for module in sorted(VALID_MODULES):
        response.set_cookie(
            module_cookie_name(module),
            create_module_jwt(
                str(user.id), user.email, user.role, module,
                user.permissions or {}, name=user.name or "",
            ),
            httponly=True, samesite="lax",
            max_age=86400, secure=_cookie_secure(),
            path=module_cookie_path(module),
        )


def _clear_module_cookies(response: Response) -> None:
    """Drop every per-module SSO cookie. Must accompany any clearing of the
    Pilot cookie: module tokens are self-contained and would otherwise stay
    valid for up to 24h after logout."""
    for module in sorted(VALID_MODULES):
        response.delete_cookie(
            module_cookie_name(module),
            path=module_cookie_path(module),
            samesite="lax", httponly=True, secure=_cookie_secure(),
        )


def _login_response(user: User, redirect_to: str = "/") -> RedirectResponse:
    token = create_jwt(str(user.id), user.email, user.role, user.modules or [], user.permissions or {}, name=user.name or "")
    response = RedirectResponse(url=_sanitize_redirect(redirect_to), status_code=302)
    response.set_cookie(
        COOKIE_NAME, token,
        httponly=True, samesite="lax",
        max_age=86400, secure=_cookie_secure(), path="/",
    )
    _set_module_cookies(response, user)
    # Clears the PKCE verifier and the nonce too — leaving them behind would
    # let a later flow reuse a verifier that has already been redeemed.
    return _clear_oauth_cookies(response)
