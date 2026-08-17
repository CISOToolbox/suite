"""NVD CVE 2.0 feed adapter.

The NVD API exposes a ``lastModStartDate`` / ``lastModEndDate`` window
filter that returns every CVE whose ``lastModified`` falls inside the
range. The window must be ≤ 120 days; we cap at 7 days to keep
responses small and to recover gracefully after a long outage.

Pagination uses ``startIndex`` / ``resultsPerPage`` (max 2000).

Auth is optional: a free API key raises the rate limit from 5 to 50
requests / 30s. We read ``NVD_API_KEY`` from the environment.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

import httpx

from .base import AlertCandidate, FeedAdapter, FeedError, FetchResult

logger = logging.getLogger("watch-feed-nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 500            # well below the 2000 cap, friendlier on slow links
MAX_WINDOW_DAYS = 7        # safety net after an outage
NVD_USER_AGENT = "CISOToolbox-Watch/0.1 (+https://cisotoolbox.org)"


class NVDFeed(FeedAdapter):
    source = "nvd"
    interval_seconds = 1800  # 30 min — NVD updates twice an hour on average

    def __init__(self) -> None:
        self._api_key = os.getenv("NVD_API_KEY", "").strip()

    async def fetch_delta(self, since: datetime | None, cursor: str) -> FetchResult:
        # NVD windows are inclusive on both ends and require ISO-8601 with
        # microseconds + UTC offset. We use the previous successful sync as
        # the lower bound, clamped to a 7-day ceiling.
        now = datetime.now(timezone.utc)
        start = since or (now - timedelta(days=1))
        if (now - start) > timedelta(days=MAX_WINDOW_DAYS):
            start = now - timedelta(days=MAX_WINDOW_DAYS)

        # Drop microseconds so the URL stays under length limits and so
        # that retries with the same boundary fetch the same set.
        start_iso = start.replace(microsecond=0).isoformat()
        end_iso = now.replace(microsecond=0).isoformat()

        params: dict[str, Any] = {
            "lastModStartDate": start_iso,
            "lastModEndDate": end_iso,
            "resultsPerPage": PAGE_SIZE,
            "startIndex": 0,
        }
        headers: dict[str, str] = {"User-Agent": NVD_USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key

        candidates_buffer: list[AlertCandidate] = []
        async with httpx.AsyncClient(timeout=self.request_timeout) as client:
            start_index = 0
            total = 1  # bootstrap the loop
            while start_index < total:
                params["startIndex"] = start_index
                try:
                    resp = await client.get(NVD_URL, params=params, headers=headers)
                except httpx.HTTPError as e:
                    raise FeedError(f"NVD HTTP error: {e}") from e
                if resp.status_code == 403:
                    raise FeedError("NVD rate-limited (403)")
                if resp.status_code >= 400:
                    raise FeedError(f"NVD HTTP {resp.status_code}")
                data = resp.json()
                total = int(data.get("totalResults", 0))
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                for entry in vulnerabilities:
                    cand = _normalise_cve(entry.get("cve") or {})
                    if cand:
                        candidates_buffer.append(cand)
                start_index += PAGE_SIZE

        logger.info("nvd fetched %s candidates (window %s → %s)",
                    len(candidates_buffer), start_iso, end_iso)

        async def _iter() -> AsyncIterator[AlertCandidate]:
            for c in candidates_buffer:
                yield c

        return FetchResult(candidates=_iter(), next_cursor=end_iso)


def _build_title(cve_id: str, summary: str) -> str:
    """Compose a human-friendly title from the CVE description.

    Format: ``CVE-YYYY-NNNN — first-sentence-of-summary``. Returns
    just the CVE id if the summary is empty or boilerplate-only.
    """
    s = (summary or "").strip()
    if not s:
        return cve_id
    # First sentence — split on ". " (period + space) which is the
    # safest separator (CVE descriptions are written in flat prose).
    # Fallback: first 180 chars.
    if ". " in s:
        first = s.split(". ", 1)[0].strip()
    else:
        first = s.strip()
    # Strip trailing punctuation that would look weird before the em-dash
    first = first.rstrip(".;: ").strip()
    if not first:
        return cve_id
    # Hard cap at 180 chars so the column stays readable. We keep enough
    # to clear the 200-char DB limit even after the prefix.
    MAX_SHORT = 180
    if len(first) > MAX_SHORT:
        # Cut on the last space before the limit to avoid mid-word break.
        cut = first[:MAX_SHORT]
        sp = cut.rfind(" ")
        if sp > 80:
            cut = cut[:sp]
        first = cut.rstrip() + "…"
    return f"{cve_id} — {first}"


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # NVD format: "2025-04-01T12:34:56.789" (no offset). Treat as UTC.
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _normalise_cve(cve: dict[str, Any]) -> AlertCandidate | None:
    cve_id = cve.get("id") or ""
    if not cve_id.startswith("CVE-"):
        return None

    summary = ""
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            summary = desc.get("value", "") or ""
            break

    # NVD doesn't ship a title field. Build a descriptive one from the
    # first sentence of the English description so the alerts table
    # shows something more informative than just the CVE id.
    title = _build_title(cve_id, summary)

    metrics = cve.get("metrics") or {}
    cvss_score: float | None = None
    cvss_vector = ""
    severity = "unknown"
    # NVD v3.1 first, fall back to v3.0, then v2.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
        cvss = primary.get("cvssData") or {}
        cvss_score = float(cvss.get("baseScore", 0) or 0) or None
        cvss_vector = cvss.get("vectorString", "") or ""
        sev = primary.get("baseSeverity") or cvss.get("baseSeverity") or ""
        if sev:
            severity = sev.lower()
        break

    refs = [r.get("url", "") for r in (cve.get("references") or []) if r.get("url")]

    affected: list[dict[str, Any]] = []
    for config in (cve.get("configurations") or []):
        for node in (config.get("nodes") or []):
            for match in (node.get("cpeMatch") or []):
                cpe = (match.get("criteria") or "").strip()
                if not cpe:
                    continue
                rng = _cpe_range(match)
                affected.append({"cpe": cpe, "version_range": rng})

    return AlertCandidate(
        source="nvd",
        external_id=cve_id,
        title=title,
        summary=summary,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        published_at=_parse_dt(cve.get("published")),
        modified_at=_parse_dt(cve.get("lastModified")),
        references=refs,
        affected=affected,
        raw=cve,
    )


def _cpe_range(match: dict[str, Any]) -> str:
    """Translate NVD's versionStartIncluding/Excluding into our shorthand."""
    parts: list[str] = []
    vsi = match.get("versionStartIncluding")
    vse = match.get("versionStartExcluding")
    vei = match.get("versionEndIncluding")
    vee = match.get("versionEndExcluding")
    if vsi:
        parts.append(f">={vsi}")
    if vse:
        parts.append(f">{vse}")
    if vei:
        parts.append(f"<={vei}")
    if vee:
        parts.append(f"<{vee}")
    return ",".join(parts)
