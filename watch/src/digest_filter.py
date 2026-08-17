"""Digest v2 filter — which alerts qualify for the per-scope critical digest.

A scope-configurable predicate selects alerts that the recipient cares
about. The thresholds live on the :class:`Scope` row:

  * ``digest_severity_min``  — string severity floor (default ``critical``).
                               Comparison uses the canonical order
                               critical > high > medium > low > unknown.
  * ``digest_include_kev``   — when True, any KEV-listed alert passes
                               regardless of severity (CISA KEV is the
                               operational "exploited in the wild" signal).
  * ``digest_cvss_min``      — float, nullable. When set, any alert with
                               ``cvss_score >= digest_cvss_min`` passes
                               regardless of severity.
  * ``digest_epss_min``      — float, nullable. Same shape, on the EPSS
                               exploit probability score.

The four rules are joined by OR — the scope is asking "wake me up for
ANY of these conditions", not all at once.
"""
from __future__ import annotations

from typing import Protocol


_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
    "": 0,
}


def _severity_rank(s: str | None) -> int:
    return _SEVERITY_ORDER.get((s or "").strip().lower(), 0)


class _AlertLike(Protocol):
    severity: str | None
    cvss_score: float | None
    epss_score: float | None
    kev_listed: bool | None


class _ScopeLike(Protocol):
    digest_severity_min: str | None
    digest_include_kev: bool | None
    digest_cvss_min: float | None
    digest_epss_min: float | None


def passes_threshold(alert: _AlertLike, scope: _ScopeLike) -> bool:
    """Return True iff ``alert`` matches any of the scope's digest
    inclusion rules.

    Order of evaluation doesn't matter (it's a logical OR), but we
    short-circuit on the cheap KEV check first because most scopes will
    keep ``digest_include_kev`` on.
    """
    # KEV gate — single boolean lookup.
    if bool(getattr(scope, "digest_include_kev", True)) and bool(getattr(alert, "kev_listed", False)):
        return True

    # Severity floor — string comparison via the canonical rank table.
    floor = getattr(scope, "digest_severity_min", None) or "critical"
    if _severity_rank(alert.severity) >= _severity_rank(floor):
        return True

    # CVSS floor — only when configured (None = gate disabled).
    cvss_min = getattr(scope, "digest_cvss_min", None)
    if cvss_min is not None and alert.cvss_score is not None and float(alert.cvss_score) >= float(cvss_min):
        return True

    # EPSS floor — same pattern.
    epss_min = getattr(scope, "digest_epss_min", None)
    if epss_min is not None and alert.epss_score is not None and float(alert.epss_score) >= float(epss_min):
        return True

    return False


def digest_suppressed(match_kind, kev_listed_at, ingested_at, since) -> bool:
    """Suppress matches that would present old CVEs as news in the digest.

    Two vectors create fresh matches on historical CVEs: the retro-match run
    at target creation (``match_kind="backfill"``), and the feed re-running
    the matcher when a source *modifies* an old entry (the alert row was
    first ingested long before the digest window). Both stay in-app for
    triage but are kept out of the "since last send" email.

    The exception is a CVE that became KEV-listed inside the window: newly
    exploited is news whatever the publication date. A KEV flip older than
    the window — or one that predates tracking (``kev_listed_at`` NULL) —
    is history like the rest: a freshly created scope matching the whole
    KEV backlog must not flood the email with years-old entries.
    """
    if kev_listed_at is not None and since is not None and kev_listed_at >= since:
        return False
    if match_kind == "backfill":
        return True
    return ingested_at is not None and since is not None and ingested_at < since
