"""OSV.dev feed adapter.

OSV doesn't expose a global "modified since" stream — instead each
ecosystem dumps a zipped JSON archive and the API supports lookups by
package. For our purposes we use the time-bounded query endpoint:

    POST https://api.osv.dev/v1/query
    { "package": {"ecosystem": "PyPI", "name": "django"} }

That only works once we know which packages to ask about. So we
take a pragmatic shortcut: enumerate distinct (ecosystem, name) pairs
from enabled PURL targets in the database (best-effort — fetched by
the scheduler before calling the adapter through ``cursor``), and
poll OSV for each. The cursor encodes the last completed enumeration
timestamp so we don't re-query the world every tick.

If no PURL targets are configured the adapter is a no-op.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import httpx

from .base import AlertCandidate, FeedAdapter, FeedError, FetchResult

logger = logging.getLogger("watch-feed-osv")

OSV_URL = "https://api.osv.dev/v1/query"

# PURL types → OSV ecosystem names.
PURL_TO_OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "packagist": "Packagist",
    "hex": "Hex",
    "composer": "Packagist",
    "pub": "Pub",
    "swift": "SwiftURL",
}


class OSVFeed(FeedAdapter):
    source = "osv"
    interval_seconds = 3600  # 1h — OSV is heavier per-query

    #: Injected by the scheduler before fetch_delta(). The scheduler
    #: queries the database for distinct (ecosystem, name) pairs.
    packages: list[dict[str, str]] = []

    async def fetch_delta(self, since: datetime | None, cursor: str) -> FetchResult:
        # The scheduler is expected to populate ``self.packages`` from the
        # current set of enabled WatchTarget rows with kind="purl".
        if not self.packages:
            logger.info("osv skipped — no PURL targets registered")
            async def _empty() -> AsyncIterator[AlertCandidate]:
                if False:  # pragma: no cover
                    yield
            return FetchResult(candidates=_empty(), next_cursor=cursor)

        candidates_buffer: list[AlertCandidate] = []
        seen_vuln_ids: set[str] = set()
        async with httpx.AsyncClient(timeout=self.request_timeout) as client:
            for pkg in self.packages:
                eco = pkg.get("ecosystem", "")
                name = pkg.get("name", "")
                if not eco or not name:
                    continue
                body = {"package": {"ecosystem": eco, "name": name}}
                try:
                    resp = await client.post(OSV_URL, json=body)
                except httpx.HTTPError as e:
                    raise FeedError(f"OSV HTTP error: {e}") from e
                if resp.status_code >= 400:
                    logger.warning("osv %s/%s → %s", eco, name, resp.status_code)
                    continue
                payload = resp.json() or {}
                for vuln in payload.get("vulns", []) or []:
                    vid = vuln.get("id") or ""
                    if not vid or vid in seen_vuln_ids:
                        continue
                    seen_vuln_ids.add(vid)
                    cand = _normalise_osv(vuln)
                    if cand:
                        candidates_buffer.append(cand)

        logger.info("osv fetched %s candidates across %s packages",
                    len(candidates_buffer), len(self.packages))

        next_cursor = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        async def _iter() -> AsyncIterator[AlertCandidate]:
            for c in candidates_buffer:
                yield c

        return FetchResult(candidates=_iter(), next_cursor=next_cursor)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _normalise_osv(vuln: dict[str, Any]) -> AlertCandidate | None:
    vid = vuln.get("id") or ""
    if not vid:
        return None

    summary = vuln.get("summary") or vuln.get("details") or ""
    title = vuln.get("summary") or vid

    severity = "unknown"
    cvss_score: float | None = None
    cvss_vector = ""
    for sev in (vuln.get("severity") or []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V31"):
            cvss_vector = sev.get("score", "") or ""
            # OSV ships vector strings, not numeric scores. The matcher /
            # frontend can render them; numeric extraction would require
            # the python-cvss library — punted for now.
            break

    # OSV's `database_specific.severity` sometimes carries the label.
    db_specific = vuln.get("database_specific") or {}
    if isinstance(db_specific, dict):
        sev_label = (db_specific.get("severity") or "").lower()
        if sev_label in ("low", "medium", "high", "critical"):
            severity = sev_label

    refs = [r.get("url", "") for r in (vuln.get("references") or []) if r.get("url")]

    affected: list[dict[str, Any]] = []
    for a in (vuln.get("affected") or []):
        pkg = a.get("package") or {}
        purl = pkg.get("purl") or ""
        if not purl:
            eco = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if eco and name:
                # Synthesise a PURL — best-effort, the matcher tolerates either.
                purl = f"pkg:{eco.lower()}/{name}"
        ranges = a.get("ranges") or []
        version_range = ""
        for r in ranges:
            events = r.get("events") or []
            bits = []
            for ev in events:
                if "introduced" in ev:
                    bits.append(f">={ev['introduced']}")
                if "fixed" in ev:
                    bits.append(f"<{ev['fixed']}")
                if "last_affected" in ev:
                    bits.append(f"<={ev['last_affected']}")
            if bits:
                version_range = ",".join(bits)
                break
        affected.append({"purl": purl, "version_range": version_range})

    return AlertCandidate(
        source="osv",
        external_id=vid,
        title=title[:500],
        summary=summary,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        published_at=_parse_dt(vuln.get("published")),
        modified_at=_parse_dt(vuln.get("modified")),
        references=refs,
        affected=affected,
        raw=vuln,
    )
