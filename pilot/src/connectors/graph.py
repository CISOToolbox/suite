"""Microsoft Graph connector for Pilot KPIs.

Five metrics are exposed:

* ``m365_secure_score`` — ``/security/secureScores?$top=1`` →
  ``currentScore / maxScore * 100`` (0-100, higher_better).
* ``defender_exposure_score`` — ``/security/exposureManagement/exposureScore``
  → ``score`` (0-100, lower_better).
* ``intune_device_compliance`` — paginate
  ``/deviceManagement/managedDevices?$select=id,complianceState`` and
  return percentage of devices with ``complianceState == 'compliant'``.
* ``entra_mfa_coverage`` — paginate
  ``/reports/authenticationMethods/userRegistrationDetails`` and return
  percentage with ``isMfaRegistered == true`` over non-guest accounts.
* ``entra_risky_users`` — count of users at risk from
  ``/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'``.

Credentials live in ``AppSettings`` under the connectors-framework
convention ``connector_m365_<field>`` with env-var fallback
``CONNECTOR_M365_<FIELD>`` (legacy ``m365_*`` AppSettings keys are
migrated by Alembic ``003_connector_rename``; legacy ``M365_*`` env vars
are still honoured as a secondary fallback). The auth flow is OAuth 2.0
client-credentials against
``https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token``;
tokens are cached in-memory for their reported ``expires_in - 60``
window so the scheduler does not re-mint on every pass.

App registration prerequisites (admin consent required):
  * ``SecurityEvents.Read.All`` — Secure Score
  * ``ThreatHunting.Read.All`` or ``SecurityAlert.Read.All`` — Defender
  * ``DeviceManagementManagedDevices.Read.All`` — Intune
  * ``UserAuthenticationMethod.Read.All`` and ``AuditLog.Read.All`` — MFA report
  * ``IdentityRiskyUser.Read.All`` — Risky users

Anything that fails (no creds, 401/403, network) returns ``None`` and
the KPI is skipped for that pass (logged at ``WARNING``).
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import AppSettings
from src.settings_crypto import decrypt_setting, is_secret_key

logger = logging.getLogger("pilot.connectors.graph")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"
SCOPE = "https://graph.microsoft.com/.default"

# Cap pagination so a misconfigured tenant cannot DoS the scheduler.
_MAX_PAGES = 50
_PAGE_SIZE = 999  # Graph max for most list endpoints

# ---------- Credentials -------------------------------------------------- #


async def _get_setting(key: str, db: AsyncSession) -> str:
    """Mirror of the helper in routes/settings.py, kept local so the
    connector layer has no inbound dependency on the routes package."""
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    raw = (s.value if s else "") or ""
    # Credentials are stored encrypted; pre-migration rows have no marker and
    # come back unchanged (see settings_crypto).
    return decrypt_setting(raw) if is_secret_key(key) else raw


async def get_credentials(db: AsyncSession) -> Optional[dict[str, str]]:
    """Return tenant_id / client_id / client_secret from AppSettings,
    falling back to env vars. Returns None when any field is missing.

    Reads the connectors-framework keys (``connector_m365_<field>`` /
    ``CONNECTOR_M365_<FIELD>``) and falls back to the legacy ``M365_*``
    env vars so ops setups that pre-date the framework keep working."""
    async def _field(field: str, legacy_env: str) -> str:
        value = await _get_setting(f"connector_m365_{field}", db)
        if value:
            return value
        return os.getenv(f"CONNECTOR_M365_{field.upper()}", "") or os.getenv(legacy_env, "")

    tenant = await _field("tenant_id", "M365_TENANT_ID")
    client_id = await _field("client_id", "M365_CLIENT_ID")
    secret = await _field("client_secret", "M365_CLIENT_SECRET")
    if not (tenant and client_id and secret):
        return None
    return {"tenant_id": tenant, "client_id": client_id, "client_secret": secret}


# ---------- Token cache -------------------------------------------------- #

# Single-process in-memory cache. The scheduler runs one pass at a time
# so concurrent token refresh races are not a concern here.
_token_cache: dict[str, tuple[str, float]] = {}  # tenant_id -> (token, expires_at)


async def _acquire_token(client: httpx.AsyncClient, creds: dict[str, str]) -> Optional[str]:
    tenant = creds["tenant_id"]
    now = time.time()
    cached = _token_cache.get(tenant)
    if cached and cached[1] > now + 30:
        return cached[0]

    url = f"{LOGIN_BASE}/{tenant}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "scope": SCOPE,
    }
    try:
        r = await client.post(url, data=data, timeout=15.0)
    except httpx.RequestError as e:
        logger.warning("Graph token fetch network error: %s", e)
        return None
    if not r.is_success:
        # Don't log the body verbatim — it may echo back a tenant hint
        # or correlation ID, but never the secret. r.text() is safe in
        # this provider.
        logger.warning("Graph token fetch failed: HTTP %s (%s)", r.status_code, r.text[:200])
        return None
    body = r.json()
    token = body.get("access_token")
    expires_in = int(body.get("expires_in") or 3600)
    if not token:
        return None
    _token_cache[tenant] = (token, now + expires_in - 60)
    return token


# ---------- Graph helpers ------------------------------------------------ #


async def _graph_get(
    client: httpx.AsyncClient, token: str, path: str
) -> Optional[dict[str, Any]]:
    url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    try:
        r = await client.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20.0)
    except httpx.RequestError as e:
        logger.warning("Graph GET %s network error: %s", path, e)
        return None
    if r.status_code in (401, 403):
        logger.warning("Graph GET %s: %s (missing scope/consent?)", path, r.status_code)
        return None
    if r.status_code == 404:
        logger.warning("Graph GET %s: 404 (endpoint unavailable on this tenant)", path)
        return None
    if not r.is_success:
        logger.warning("Graph GET %s: HTTP %s", path, r.status_code)
        return None
    try:
        return r.json()
    except ValueError:
        return None


async def _graph_paginate(
    client: httpx.AsyncClient, token: str, path: str
) -> list[dict[str, Any]]:
    """Walk @odata.nextLink up to ``_MAX_PAGES`` pages. Returns the
    collected ``value`` list (empty on first-page failure)."""
    out: list[dict[str, Any]] = []
    next_url: Optional[str] = path
    pages = 0
    while next_url and pages < _MAX_PAGES:
        body = await _graph_get(client, token, next_url)
        if body is None:
            break
        values = body.get("value")
        if isinstance(values, list):
            out.extend(values)
        next_url = body.get("@odata.nextLink")
        pages += 1
    if pages >= _MAX_PAGES:
        logger.warning("Graph paginate %s: hit page cap (%d)", path, _MAX_PAGES)
    return out


# ---------- Resolvers ---------------------------------------------------- #


async def resolve_m365_secure_score(
    client: httpx.AsyncClient, token: str
) -> Optional[float]:
    body = await _graph_get(client, token, "/security/secureScores?$top=1")
    if not body:
        return None
    items = body.get("value") or []
    if not items:
        return None
    cur = items[0].get("currentScore")
    mx = items[0].get("maxScore")
    if cur is None or not mx:
        return None
    try:
        return round(float(cur) / float(mx) * 100.0, 1)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


async def resolve_defender_exposure_score(
    client: httpx.AsyncClient, token: str
) -> Optional[float]:
    # Microsoft Security Exposure Management — current exposure score.
    # On tenants without MSEM licensing this returns 404 → None.
    body = await _graph_get(
        client, token, "/security/exposureManagement/exposureScore"
    )
    if not body:
        return None
    score = body.get("score")
    if score is None:
        return None
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


async def resolve_intune_device_compliance(
    client: httpx.AsyncClient, token: str
) -> Optional[float]:
    rows = await _graph_paginate(
        client,
        token,
        f"/deviceManagement/managedDevices?$select=id,complianceState&$top={_PAGE_SIZE}",
    )
    if not rows:
        return None
    total = len(rows)
    compliant = sum(1 for r in rows if (r.get("complianceState") or "").lower() == "compliant")
    return round(compliant / total * 100.0, 1)


async def resolve_entra_mfa_coverage(
    client: httpx.AsyncClient, token: str
) -> Optional[float]:
    rows = await _graph_paginate(
        client,
        token,
        f"/reports/authenticationMethods/userRegistrationDetails?$top={_PAGE_SIZE}",
    )
    if not rows:
        return None
    # Exclude guests so the coverage figure tracks the internal posture.
    members = [r for r in rows if (r.get("userType") or "member").lower() == "member"]
    if not members:
        return None
    mfa_ok = sum(1 for r in members if r.get("isMfaRegistered") is True)
    return round(mfa_ok / len(members) * 100.0, 1)


async def resolve_entra_risky_users(
    client: httpx.AsyncClient, token: str
) -> Optional[float]:
    body = await _graph_get(
        client,
        token,
        "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$count=true&$top=1",
    )
    if body is None:
        return None
    # When $count=true is honoured Graph echoes @odata.count; otherwise
    # we fall back to paginating the result set (cheap when atRisk is
    # small).
    count = body.get("@odata.count")
    if isinstance(count, int):
        return float(count)
    rows = await _graph_paginate(
        client,
        token,
        "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$top=999",
    )
    return float(len(rows))


# ---------- Entry point used by the scheduler --------------------------- #


# Maps the catalogue's ``source_metric`` to a resolver coroutine. The
# scheduler iterates KPIs with ``source_module='connector'`` and looks
# the metric up here; unknown metrics return None (skip + log).
_RESOLVERS = {
    "m365_secure_score": resolve_m365_secure_score,
    "defender_exposure_score": resolve_defender_exposure_score,
    "intune_device_compliance": resolve_intune_device_compliance,
    "entra_mfa_coverage": resolve_entra_mfa_coverage,
    "entra_risky_users": resolve_entra_risky_users,
}

# Deterministic demo values (MedSecure M365/Entra posture) returned when no
# credentials are configured, so the indicators populate offline. Real
# credentials switch every metric back to live Microsoft Graph queries.
_DEMO = {
    "m365_secure_score": 82.0,        # >= target 80 → green
    "defender_exposure_score": 16.0,  # <= target 20 → green
    "intune_device_compliance": 96.0, # >= target 95 → green
    "entra_mfa_coverage": 100.0,      # >= target 100 → green
    "entra_risky_users": 3.0,         # > target 0 (< amber 5) → amber (realistic)
}


async def _demo_enabled(db: AsyncSession) -> bool:
    """Demo mode is on unless explicitly disabled in Pilot settings (demo_mode='false')."""
    return (await _get_setting("demo_mode", db)) != "false"


async def resolve_metric(metric: str, db: AsyncSession) -> Optional[float]:
    """Public entry point. Returns None on missing creds / unknown
    metric / soft failure (the scheduler treats None as 'skip')."""
    fn = _RESOLVERS.get(metric)
    if fn is None:
        return None
    creds = await get_credentials(db)
    if creds is None:
        if await _demo_enabled(db):
            logger.info("Graph connector: no credentials — demo value for %s", metric)
            return _DEMO.get(metric)
        return None
    async with httpx.AsyncClient(timeout=20.0) as client:
        token = await _acquire_token(client, creds)
        if not token:
            return None
        return await fn(client, token)


async def test_credentials(db: AsyncSession) -> tuple[bool, str]:
    """Smoke test used by the admin route. Acquires a token and probes
    the Secure Score endpoint — the same endpoint the first KPI uses,
    so success here mirrors what the scheduler will see. Avoids asking
    for ``Organization.Read.All`` just to validate the test."""
    creds = await get_credentials(db)
    if creds is None:
        return True, "Mode démo (aucune credential M365 configurée) — valeurs simulées."
    async with httpx.AsyncClient(timeout=15.0) as client:
        token = await _acquire_token(client, creds)
        if not token:
            return False, "Token acquisition failed (check tenant_id / client_id / client_secret)"
        body = await _graph_get(client, token, "/security/secureScores?$top=1")
        if body is None:
            return (
                False,
                "Token acquired but Secure Score call failed "
                "(check SecurityEvents.Read.All admin consent)",
            )
        return True, "ok"
