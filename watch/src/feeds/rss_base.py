"""Shared helper for plain-RSS national-CERT style feeds.

Sources like CISA, CERT-EU, NCSC-UK ship advisories as RSS/Atom streams
with the same shape: an item has a permalink, title, summary, pub date.
No CPEs, no structured severity — just narrative the keyword matcher
can scan.

Rather than duplicate the CERT-FR adapter for every new source, this
module exposes :class:`SimpleRSSFeed`, parameterized by:

* a stable ``source`` slug (used for ``Alert.source`` + UI filter),
* one or more ``(kind, url)`` pairs (the kind label is only kept on
  ``raw.kind`` for debugging),
* a default ``severity`` applied to every item (CISA Cybersec → "high",
  CISA ICS → "high", CERT-EU → "medium", NCSC-UK → "medium"),
* an optional ``id_regex`` to extract a stable bulletin id from the
  title (e.g. AA24-… for CISA).

CERT-FR keeps its dedicated adapter because it carries per-kind
severity heuristics ("alerte" → critical, "cti" → high) that don't
generalise cleanly.
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

logger = logging.getLogger("watch-feed-rss")

_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class SimpleRSSFeed(FeedAdapter):
    """Parameterized RSS adapter — one HTTP request per configured URL.

    Subclasses set ``source``, ``urls``, ``default_severity`` and
    (optionally) ``id_regex``. The fetch logic mirrors CERT-FR.
    """

    #: list of ``(kind, url)`` pairs. ``kind`` ends up in ``raw.kind``
    #: only — it has no effect on severity or matching.
    urls: list[tuple[str, str]] = []

    #: severity applied to every item unless an override is set in the
    #: subclass via ``_severity_for(entry, kind)``.
    default_severity: str = "medium"

    #: optional regex to extract a stable bulletin id from the title.
    id_regex: re.Pattern[str] | None = None

    interval_seconds = 3600  # 1h — RSS sources update a few times per day

    def _severity_for(self, entry: object, kind: str) -> str:
        """Hook for subclasses to override severity per-item.

        Default: return ``self.default_severity`` for every item.
        """
        return self.default_severity

    async def fetch_delta(self, since: datetime | None, cursor: str) -> FetchResult:
        candidates: list[AlertCandidate] = []
        # NB: a bare "CISOToolbox-Watch/0.1" UA gets 403'd by CISA's WAF.
        # We declare ourselves as a Mozilla-prefixed RSS reader so the
        # well-known WAF rules let the request through, with the project
        # URL appended for transparency to the source operator.
        async with httpx.AsyncClient(
            timeout=self.request_timeout,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (CISOToolbox-Watch RSS reader; "
                    "+https://cisotoolbox.org)"
                ),
                "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
            },
            follow_redirects=True,
        ) as client:
            for kind, url in self.urls:
                try:
                    resp = await client.get(url)
                except httpx.HTTPError as e:
                    raise FeedError(f"{self.source} HTTP error ({kind}): {e}") from e
                if resp.status_code >= 400:
                    logger.warning("%s %s → %s", self.source, kind, resp.status_code)
                    continue
                parsed = feedparser.parse(resp.text)
                for entry in parsed.entries or []:
                    cand = self._normalise_entry(entry, kind, since)
                    if cand:
                        candidates.append(cand)

        logger.info("%s fetched %s candidates", self.source, len(candidates))
        next_cursor = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        async def _iter() -> AsyncIterator[AlertCandidate]:
            for c in candidates:
                yield c

        return FetchResult(candidates=_iter(), next_cursor=next_cursor)

    def _normalise_entry(
        self, entry: object, kind: str, since: datetime | None
    ) -> AlertCandidate | None:
        eid = getattr(entry, "id", "") or getattr(entry, "link", "")
        if not eid:
            return None

        title = getattr(entry, "title", "") or ""
        summary = getattr(entry, "summary", "") or ""
        link = getattr(entry, "link", "") or ""

        pub_str = getattr(entry, "published", "") or getattr(entry, "updated", "")
        published = _parse_dt(pub_str)
        if since and published and published < since:
            return None

        # Stable bulletin id when the regex matches the title; otherwise
        # fall back to the entry id / link so upsert remains idempotent.
        external_id = ""
        if self.id_regex is not None:
            m = self.id_regex.search(title)
            if m:
                external_id = m.group(0)
        if not external_id:
            external_id = eid

        cves = sorted(set(_CVE_RX.findall(summary)))
        affected: list[dict] = [{"keyword_hint": title}]
        for cve in cves:
            affected.append({"cve_ref": cve.upper()})

        return AlertCandidate(
            source=self.source,
            external_id=external_id[:200],
            title=title[:500],
            summary=summary,
            severity=self._severity_for(entry, kind),
            published_at=published,
            modified_at=published,
            references=[link] if link else [],
            affected=affected,
            raw={"kind": kind, "title": title, "link": link},
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
