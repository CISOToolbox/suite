"""CISA KEV (Known Exploited Vulnerabilities) feed adapter.

The catalog is a single JSON document refreshed daily. We download
it in full each cycle (it's small — a few hundred KB) and emit one
candidate per row. The match value is the CVE id which lets the
matcher set kev_listed=true on the corresponding NVD alert via the
post-ingest merge step.

We also emit standalone KEV "alerts" so users without CPE targets
(only keyword) can still triage exploited CVEs against their stack.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import httpx

from .base import AlertCandidate, FeedAdapter, FeedError, FetchResult

logger = logging.getLogger("watch-feed-kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVFeed(FeedAdapter):
    source = "kev"
    interval_seconds = 21600  # 6h — CISA publishes new entries ~once/day

    async def fetch_delta(self, since: datetime | None, cursor: str) -> FetchResult:
        async with httpx.AsyncClient(timeout=self.request_timeout) as client:
            try:
                resp = await client.get(KEV_URL)
            except httpx.HTTPError as e:
                raise FeedError(f"KEV HTTP error: {e}") from e
            if resp.status_code >= 400:
                raise FeedError(f"KEV HTTP {resp.status_code}")
            data = resp.json() or {}

        vulns = data.get("vulnerabilities", []) or []
        candidates: list[AlertCandidate] = []
        for v in vulns:
            cve_id = v.get("cveID") or ""
            if not cve_id:
                continue
            candidates.append(AlertCandidate(
                source="kev",
                external_id=cve_id,
                title=v.get("vulnerabilityName", "") or cve_id,
                summary=v.get("shortDescription", "") or "",
                severity="critical",  # KEV → actively exploited → critical posture
                kev_listed=True,
                published_at=_parse_date(v.get("dateAdded")),
                modified_at=_parse_date(v.get("dateAdded")),
                references=[],
                affected=[{
                    "vendor": v.get("vendorProject", "") or "",
                    "product": v.get("product", "") or "",
                    "cpe": "",  # KEV doesn't ship CPEs
                }],
                raw=v,
            ))

        logger.info("kev fetched %s exploited entries", len(candidates))
        next_cursor = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        async def _iter() -> AsyncIterator[AlertCandidate]:
            for c in candidates:
                yield c

        return FetchResult(candidates=_iter(), next_cursor=next_cursor)


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # KEV uses "YYYY-MM-DD".
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
