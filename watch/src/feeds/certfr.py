"""CERT-FR feed adapter — French national CERT advisories (RSS).

CERT-FR ships three RSS streams that we consolidate into one feed:
  * avis    — vendor advisories (the bulk).
  * alerte — major alerts (rare but high-priority).
  * cti    — threat intelligence (campaigns, IOCs).

Each item has a permalink, title, publication date and a one-paragraph
description. We don't deep-fetch the HTML page — the LLM analysis
step (phase 4) can pull more context on demand.

CERT-FR items don't carry CPEs. We expose the vendor/product fragments
in ``affected`` so the keyword matcher can find them, plus a synthetic
"keyword" hint built from the title.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator

import feedparser
import httpx
from dateutil import parser as dateparser

from .base import AlertCandidate, FeedAdapter, FeedError, FetchResult

logger = logging.getLogger("watch-feed-certfr")

CERTFR_FEEDS = [
    ("avis", "https://www.cert.ssi.gouv.fr/avis/feed/"),
    ("alerte", "https://www.cert.ssi.gouv.fr/alerte/feed/"),
    ("cti", "https://www.cert.ssi.gouv.fr/cti/feed/"),
]

_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CERTFRFeed(FeedAdapter):
    source = "certfr"
    interval_seconds = 3600  # 1h — RSS updates a handful of times per day

    async def fetch_delta(self, since: datetime | None, cursor: str) -> FetchResult:
        candidates: list[AlertCandidate] = []
        async with httpx.AsyncClient(timeout=self.request_timeout,
                                     headers={"User-Agent": "CISOToolbox-Watch/0.1"}) as client:
            for kind, url in CERTFR_FEEDS:
                try:
                    resp = await client.get(url)
                except httpx.HTTPError as e:
                    raise FeedError(f"CERT-FR HTTP error ({kind}): {e}") from e
                if resp.status_code >= 400:
                    logger.warning("certfr %s → %s", kind, resp.status_code)
                    continue
                parsed = feedparser.parse(resp.text)
                for entry in parsed.entries or []:
                    cand = _normalise_entry(entry, kind, since)
                    if cand:
                        candidates.append(cand)

        logger.info("certfr fetched %s candidates", len(candidates))
        next_cursor = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        async def _iter() -> AsyncIterator[AlertCandidate]:
            for c in candidates:
                yield c

        return FetchResult(candidates=_iter(), next_cursor=next_cursor)


def _normalise_entry(entry: object, kind: str, since: datetime | None) -> AlertCandidate | None:
    # feedparser returns dict-like FeedParserDict objects.
    eid = getattr(entry, "id", "") or getattr(entry, "link", "")
    if not eid:
        return None

    title = getattr(entry, "title", "") or ""
    summary = getattr(entry, "summary", "") or ""

    pub_str = getattr(entry, "published", "") or getattr(entry, "updated", "")
    published = _parse_dt(pub_str)
    # Skip stale rows older than the previous successful sync.
    if since and published and published < since:
        return None

    # CERT-FR titles usually look like "CERTFR-2025-AVI-0123" — use the
    # bulletin id as external_id when present, otherwise fall back to the URL.
    bull_id = ""
    m = re.search(r"CERTFR-\d{4}-(AVI|ALE|CTI)-\d+", title)
    if m:
        bull_id = m.group(0)
    external_id = bull_id or eid

    # Extract referenced CVEs from the summary text — used by the
    # matcher to up-rank CERT-FR items that cover already-known CVEs.
    cves = sorted(set(_CVE_RX.findall(summary)))

    affected = [{"keyword_hint": title}]
    for cve in cves:
        affected.append({"cve_ref": cve.upper()})

    return AlertCandidate(
        source="certfr",
        external_id=external_id,
        title=title[:500],
        summary=summary,
        severity=("critical" if kind == "alerte" else "high" if kind == "cti" else "medium"),
        published_at=published,
        modified_at=published,
        references=[getattr(entry, "link", "")] if getattr(entry, "link", "") else [],
        affected=affected,
        raw={"kind": kind, "title": title, "link": getattr(entry, "link", "")},
    )


def _parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        dt = dateparser.parse(s)
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
