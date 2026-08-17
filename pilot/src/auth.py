"""Pilot's own auth module (the modules use shared/python/auth_common.py).

THE `None` CONTRACT — read this before writing an endpoint
----------------------------------------------------------
`get_current_user()` returns `Optional[User]`, and `None` has exactly ONE
meaning: **authentication is disabled** (`auth_enabled()` is False, i.e.
AUTH_MODE=none). It NEVER means "anonymous caller" — a caller with no
valid session gets a 401 raised inside the dependency and never reaches
the handler at all. So, in a handler body:

    auth_enabled() is False  <=>  user is None  <=>  caller is admin

Two mistakes follow from forgetting this, and both are real bugs we shipped:

  * treating `None` as unauthenticated — `if user is None: raise 401` locks
    every caller out in AUTH_MODE=none (AUTH-02, 26 endpoints);
  * reading `user.<attr>` with no guard — `AttributeError` -> 500 in
    AUTH_MODE=none (AUTH-02 follow-up, 42 accesses in `watch`).

The rules, in order of preference:

  1. Test the posture, not the sentinel: `auth_enabled()` and
     `require_admin(user)` handle `None` correctly. Prefer them.
  2. Need a value off the user? Use the ownership idiom
     `user.id if user else None`. Consequence, accepted: objects created
     in AUTH_MODE=none have NO owner.
  3. Need a real identity (a NOT NULL owner_id/user_id FK)? Call
     `require_identity(user)` — it answers a clear 503 instead of a 500.
  4. Want a 401 for an anonymous caller? You already have it: the
     dependency raised it. Do not re-check.

`tests/test_auth_sentinel.py` enforces this across the 9 modules + Pilot.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request
import jwt
from jwt.exceptions import InvalidTokenError as JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.models import User

JWT_SECRET = os.getenv("JWT_SECRET", "")
# Kept identical to auth_common._MIN_JWT_SECRET_LEN — the two posture
# checks guard the same credential and must not drift apart.
_MIN_JWT_SECRET_LEN = 32
JWT_ALGORITHM = "HS256"


def _session_ttl_hours() -> int:
    """Session lifetime in hours, from JWT_EXPIRY_HOURS (default 24).

    A stateless JWT cannot be revoked before it expires, so this bounds how
    long a deleted or downgraded account keeps access. Pilot mints the module
    tokens, so this value governs the whole suite's SSO session. Tighten it
    (e.g. 4–8h) to shrink the window; clamped to 1h–7d, falls back to 24 on a
    non-numeric value. Kept in sync with shared/python/auth_common.py."""
    try:
        return min(168, max(1, int(os.getenv("JWT_EXPIRY_HOURS", "24"))))
    except ValueError:
        return 24


JWT_EXPIRY_HOURS = _session_ttl_hours()
COOKIE_NAME = "pilot_token"
# Suite SSO trust domains (kept in sync with shared/python/auth_common.py).
#
# Pilot is the single issuer (iss="ciso-pilot"), but there is no longer a
# single suite-wide token: Pilot mints one token PER MODULE, each signed
# with a key derived from JWT_SECRET for that module only (AUTH-01).
#   - Pilot's own session cookie: aud="ciso-suite", key=HKDF(secret,"ciso-suite")
#   - Module cookie <m>_token:    aud="ciso-module:<m>", key=HKDF(secret,"ciso-module:<m>")
# Rule: the signing key is derived with info = the token's audience. A
# module therefore only ever holds its own key — compromising one no
# longer yields the key of the other eight, nor JWT_SECRET itself (HKDF
# is one-way). Tokens minted before this change do not verify → re-login.
JWT_ISSUER = "ciso-pilot"
JWT_AUDIENCE = "ciso-suite"
JWT_HKDF_SALT = b"ciso-suite/jwt-key/v1"


def _hkdf_sha256(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869 extract-then-expand), stdlib only.

    Byte-for-byte identical to the modules' implementation in
    shared/python/auth_common.py — the two MUST agree, since Pilot signs
    what the modules verify. Cross-checked against
    cryptography.hazmat.primitives.kdf.hkdf.HKDF in the test suite.
    """
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_jwt_key(secret: str, info: str) -> bytes:
    """Signing key for one trust domain. `info` is the token audience."""
    if not secret:
        return b""
    return _hkdf_sha256(secret.encode(), JWT_HKDF_SALT, info.encode())


def module_audience(module: str) -> str:
    return f"ciso-module:{module or 'module'}"


def module_cookie_name(module: str) -> str:
    """Cookie Pilot drops for `module`. Convention shared with the modules
    (shared/python/auth_common.module_cookie_name) — keep both in sync."""
    return f"{module}_token"


def module_cookie_path(module: str) -> str:
    """Path the module is served under at the edge (nginx `location
    ^~ /<module>/`). Scoping the cookie there keeps the browser from
    shipping all nine module tokens on every single request, and keeps one
    module from ever seeing another's cookie."""
    return f"/{module}/"


# Pilot's own session key. Derived like every other one, so the raw
# JWT_SECRET is never used as a signing key anywhere in the suite.
PILOT_JWT_KEY = derive_jwt_key(JWT_SECRET, JWT_AUDIENCE)
# Auth is disabled ONLY when explicitly opted into via AUTH_MODE=none (dev/test).
# assert_auth_posture() refuses to boot with an empty JWT_SECRET otherwise, so an
# unconfigured production can never silently serve every route as admin.
AUTH_MODE = os.getenv("AUTH_MODE", "pilot")

VALID_MODULES = {"risk", "compliance", "vendor", "audit", "asset", "access", "surface", "appsec", "watch"}
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


def auth_enabled() -> bool:
    """Is any identity actually being verified?

    THE authoritative predicate for the auth posture, and the one to branch
    on. False means AUTH_MODE=none (dev/test) — every route is served as
    admin and `get_current_user()` yields `None`. See "THE `None` CONTRACT"
    at the top of this module: `not auth_enabled()` is the *cause*,
    `user is None` is only its visible effect. Branch on the cause.
    """
    if AUTH_MODE == "none":
        return False
    return bool(JWT_SECRET)


def assert_auth_posture() -> None:
    """Fail closed unless AUTH_MODE=none is explicit. Call once at startup.

    Kept in sync with shared/python/auth_common.assert_auth_posture (Pilot has
    its own auth module by design). An empty JWT_SECRET makes auth_enabled()
    False and serves every route as admin — refuse to boot unless disabling
    auth was requested on purpose.
    """
    if AUTH_MODE == "none":
        return
    if not JWT_SECRET:
        raise RuntimeError(
            "JWT_SECRET is empty but AUTH_MODE is not 'none'. Set JWT_SECRET "
            "to enable authentication (production), or set AUTH_MODE=none to "
            "run without authentication (test only). Refusing to start."
        )
    # Non-empty was the only bar, so "admin123" booted happily. Pilot mints the
    # token for every module from this root secret, and the HKDF info strings
    # that derive each module key are public in auth_common — recovering a weak
    # secret offline from one captured cookie forges admin across the suite.
    # Same floor as auth_common._MIN_JWT_SECRET_LEN and crypto._MIN_KEY_LEN.
    if len(JWT_SECRET) < _MIN_JWT_SECRET_LEN:
        raise RuntimeError(
            f"JWT_SECRET is too short ({len(JWT_SECRET)} chars): minimum "
            f"{_MIN_JWT_SECRET_LEN}. It is the root secret every module's "
            "session key is derived from — generate one with "
            "`openssl rand -hex 32`. Refusing to start."
        )


def create_jwt(user_id: str, email: str, role: str, modules: list[str], permissions: dict | None = None, name: str = "") -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "name": name or "",
        "role": role,
        "modules": modules,
        "permissions": permissions or {},
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, PILOT_JWT_KEY, algorithm=JWT_ALGORITHM)


def create_module_jwt(
    user_id: str,
    email: str,
    role: str,
    module: str,
    permissions: dict | None = None,
    name: str = "",
) -> str:
    """Mint the SSO token for one module, signed with that module's key.

    Deliberately narrower than the Pilot session token: no `modules` list
    and only this module's entry from the permissions map, so a token
    stolen from one module leaks nothing about the user's rights
    elsewhere. The global `role` stays (a suite admin is admin in every
    module — product decision, unchanged here).
    """
    perms = permissions or {}
    scoped = {module: perms[module]} if module in perms else {}
    payload = {
        "sub": user_id,
        "email": email,
        "name": name or "",
        "role": role,
        "permissions": scoped,
        "iss": JWT_ISSUER,
        "aud": module_audience(module),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(
        payload,
        derive_jwt_key(JWT_SECRET, module_audience(module)),
        algorithm=JWT_ALGORITHM,
    )


def decode_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        PILOT_JWT_KEY,
        algorithms=[JWT_ALGORITHM],
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
    )


async def _resolve_user(
    request: Request,
    db: AsyncSession,
) -> Optional[User]:
    """Decode JWT + lookup user. Returns None when auth is disabled,
    raises 401 on missing/invalid token. Does NOT check roles."""
    if not auth_enabled():
        return None
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_jwt(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.get(User, payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Standard dependency — blocks pending users.

    Returns `None` **only** when `auth_enabled()` is False (AUTH_MODE=none):
    the caller is admin and there is no identity to attribute anything to.
    An unauthenticated caller never gets here — this raises 401 first. Do
    not re-interpret the `None`; see "THE `None` CONTRACT" above.
    """
    user = await _resolve_user(request, db)
    if user is not None and user.role == "pending":
        raise HTTPException(status_code=403, detail="Account pending approval")
    return user


async def get_current_user_permissive(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """For /auth/me — always returns the user, even if pending.
    The frontend decides what to show.

    Same `None` contract as `get_current_user`: `None` = auth disabled,
    not anonymous.
    """
    return await _resolve_user(request, db)


def require_identity(user: Optional[User]) -> User:
    """Narrow the sentinel to a real user, or refuse the request explicitly.

    For the few endpoints whose data model is keyed on *who* you are — a
    NOT NULL `owner_id` / `user_id` foreign key. With auth disabled there
    is no identity to key the row on and no row can be written, so answer
    503 with the actual cause rather than letting `user.id` raise
    AttributeError -> 500.

    Use this ONLY when an identity is structurally required. For plain
    ownership stamping prefer `user.id if user else None`, which leaves
    the object unowned in AUTH_MODE=none — the accepted trade-off.
    """
    if user is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "This endpoint records a per-user row and cannot be served "
                "while authentication is disabled (AUTH_MODE=none)."
            ),
        )
    return user


def require_admin(user: Optional[User]) -> None:
    """Admin gate. `user is None` = auth disabled = admin: pass through."""
    if user is None:
        return
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


def require_writer(user: Optional[User]) -> None:
    """Refuse a read-only account on a write endpoint.

    `viewer` was accepted at user creation but enforced nowhere: the only gate
    on project and measure writes was `_can_access` (ownership / share), which
    says *which* projects you may touch, not whether you may write at all. A
    viewer could therefore create projects and edit consolidated measures —
    including the write-back to the source module over SERVICE_TOKEN.

    `user is None` = auth disabled = admin: pass through, same contract as
    require_admin.
    """
    if user is None:
        return
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Read-only account")


def verify_service_token(request: Request) -> None:
    token = request.headers.get("X-Service-Token", "")
    import secrets as _secrets
    if not SERVICE_TOKEN or not _secrets.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid service token")
