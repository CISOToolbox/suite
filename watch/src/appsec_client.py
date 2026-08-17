"""Server-to-server client for AppSec /internal endpoints.

Used by the Watch alert detail view to surface the SBOM impact of an
alert (which applications carry an affected package). All calls are
guarded with the SERVICE_TOKEN shared across the suite — when AppSec
is not deployed alongside Watch (``APPSEC_URL`` unset), the client
returns an empty payload so the frontend can render a "not configured"
hint without surfacing an error.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("watch.appsec_client")

APPSEC_URL = os.getenv("APPSEC_URL", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
TIMEOUT_S = 8.0


def is_configured() -> bool:
    return bool(APPSEC_URL and SERVICE_TOKEN)


async def sbom_impact(cve_id: str | None, affected: list[dict[str, Any]]) -> dict[str, Any]:
    """Call POST {APPSEC_URL}/api/internal/sbom/impact and return its JSON body.

    Returns ``{"configured": False, ...}`` if AppSec is not deployed
    alongside Watch. Returns ``{"error": "..."}`` on transport or 5xx
    errors so the caller can degrade gracefully (the alert detail view
    falls back to "AppSec unavailable" without breaking the modal).
    """
    if not is_configured():
        return {
            "configured": False,
            "cve_id": cve_id,
            "matched_findings": [],
            "matched_sbom": [],
            "applications": [],
        }

    url = APPSEC_URL.rstrip("/") + "/api/internal/sbom/impact"
    headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}
    payload = {"cve_id": cve_id or "", "affected": affected or []}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_S) as client:
            r = await client.post(url, headers=headers, json=payload)
        if r.status_code >= 500:
            logger.warning("AppSec /sbom/impact returned %s: %s", r.status_code, r.text[:200])
            return {"configured": True, "error": f"appsec_{r.status_code}",
                    "matched_findings": [], "matched_sbom": [], "applications": []}
        r.raise_for_status()
        data = r.json()
        data["configured"] = True
        return data
    except httpx.HTTPError as e:
        logger.warning("AppSec /sbom/impact call failed: %s", e)
        return {"configured": True, "error": "appsec_unreachable",
                "matched_findings": [], "matched_sbom": [], "applications": []}
