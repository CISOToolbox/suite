"""Regression: a standalone OIDC sign-in always checks the id_token's issuer.

When userinfo is not available, the id_token is the identity assertion and is
verified against the provider's keys. Its issuer was taken from the discovery
document only, and an empty issuer turns the check off: a discovery document
without `issuer` let an id_token from any issuer signed by those keys through.
The configured `OIDC_ISSUER` is now the fallback.

Exercised on appsec's copy of the shared source (auth_routes_common.py is
identical in every module).
"""
from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/appsec_test")
os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import auth_routes_common as routes_auth  # noqa: E402

_ISSUER = "https://idp.medsecure.example"


def _callback(monkeypatch, discovery):
    seen = {}

    class _Client:
        def __init__(self, **_):
            self.token = None

        async def fetch_token(self, *_, **__):
            return {"id_token": "header.payload.sig"}

    async def _endpoints():
        return discovery

    async def _verify(id_token, jwks_url, audience, issuer=None):
        seen["issuer"] = issuer
        raise ValueError("stop here")

    monkeypatch.setattr(routes_auth, "OIDC_ISSUER", _ISSUER)
    monkeypatch.setattr(routes_auth, "_oidc_configured", lambda: True)
    monkeypatch.setattr(routes_auth, "_get_oidc_endpoints", _endpoints)
    monkeypatch.setattr(routes_auth, "_verify_oauth_state", lambda request: None)
    monkeypatch.setattr(routes_auth, "AsyncOAuth2Client", _Client)
    monkeypatch.setattr(routes_auth, "_verify_id_token_jwks", _verify)

    request = SimpleNamespace(cookies={}, url="https://appsec.medsecure.example/auth/callback/oidc?code=x")
    resp = asyncio.run(routes_auth.callback_oidc(request, None))
    assert resp.headers["location"] == "/login.html?error=token_verify_failed"
    return seen["issuer"]


_NO_USERINFO = {"token_endpoint": _ISSUER + "/token", "jwks_uri": _ISSUER + "/jwks"}


def test_discovery_without_issuer_falls_back_to_the_configured_one(monkeypatch):
    assert _callback(monkeypatch, dict(_NO_USERINFO)) == _ISSUER


def test_discovery_issuer_is_used_when_present(monkeypatch):
    discovery = dict(_NO_USERINFO, issuer=_ISSUER + "/realms/medsecure")
    assert _callback(monkeypatch, discovery) == _ISSUER + "/realms/medsecure"
