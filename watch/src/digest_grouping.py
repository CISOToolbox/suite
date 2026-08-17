"""Digest v2 grouping — merge alerts that describe the same vulnerability.

CISA KEV mirrors a subset of NVD CVEs: every KEV entry's ``external_id``
is the same ``CVE-YYYY-NNNNN`` as the corresponding NVD row. Without
grouping, a user with both feeds enabled sees the same CVE twice in
the digest (once as ``nvd:CVE-2025-1234``, once as ``kev:CVE-2025-1234``).

This module folds those duplicates into a single :class:`AlertGroup`
that exposes:

  * a canonical ``cve_id`` (``"CVE-YYYY-NNNNN"`` when available)
  * the underlying :class:`Alert` rows sorted by priority — the NVD row
    is preferred as the "primary" because its CVSS vector and affected
    component data are richer than KEV's. The KEV row is kept as a
    sibling so the email can show "KEV listed" as a distinct bandeau.
  * convenience flags (``kev_listed``, max severity, max CVSS/EPSS)

Threat-digest grouping (ThreatGroup / group_threat_matches) was removed
in M22 when the threat section moved to a free-prompt + Claude
web_search model. AlertGroup remains the only grouping primitive,
used exclusively by the vuln digest.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

try:
    from .risk_scorer import RiskAssessment, score_group
    from .cve_timeline import CveTimeline, build_timeline
except ImportError:  # standalone unit-test import (sys.path injection)
    from risk_scorer import RiskAssessment, score_group  # type: ignore
    from cve_timeline import CveTimeline, build_timeline  # type: ignore


# CVE id pattern — matches ``CVE-YYYY-NN..N`` with at least four digits
# in the sequence portion (the CVE program requires 4+).
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _extract_cve_id(alert) -> str | None:
    """Best-effort canonical CVE id for an alert.

    For ``source in {nvd, kev}`` the ``external_id`` IS the CVE. For
    others we fall back to scanning the title and references; if nothing
    looks like a CVE, return None and let the alert stand alone.
    """
    src = (getattr(alert, "source", "") or "").lower()
    ext = (getattr(alert, "external_id", "") or "").strip()
    if src in ("nvd", "kev") and ext.upper().startswith("CVE-"):
        return ext.upper()
    # Fallback: scan title + refs for the first CVE-shaped token.
    haystack = " ".join([
        ext,
        (getattr(alert, "title", "") or ""),
        " ".join(str(r) for r in (getattr(alert, "references_json", None) or [])),
    ])
    m = _CVE_RE.search(haystack)
    return m.group(1).upper() if m else None


@dataclass
class AlertGroup:
    """One vulnerability, one card in the digest.

    ``primary`` is the alert we hand to the LLM analyzer and use as the
    visible title. ``siblings`` are duplicates from other feeds (KEV
    flag, vendor advisory mirror) that contribute *signals* but don't
    deserve their own card.
    """
    key: str                          # CVE id, or "{source}:{external_id}" if no CVE
    primary: object                   # the richest Alert for analysis
    siblings: list = field(default_factory=list)

    @property
    def cve_id(self) -> str | None:
        return self.key if self.key.upper().startswith("CVE-") else None

    @property
    def kev_listed(self) -> bool:
        return bool(getattr(self.primary, "kev_listed", False)) or any(
            getattr(a, "kev_listed", False) for a in self.siblings
        )

    @property
    def max_cvss(self) -> float | None:
        scores = [getattr(a, "cvss_score", None) for a in [self.primary, *self.siblings]]
        scores = [s for s in scores if s is not None]
        return max(scores) if scores else None

    @property
    def max_epss(self) -> float | None:
        scores = [getattr(a, "epss_score", None) for a in [self.primary, *self.siblings]]
        scores = [s for s in scores if s is not None]
        return max(scores) if scores else None

    @property
    def severity(self) -> str:
        rank = -1
        best = "unknown"
        for a in [self.primary, *self.siblings]:
            s = (getattr(a, "severity", "") or "unknown").lower()
            r = _SEVERITY_ORDER.get(s, 0)
            if r > rank:
                rank, best = r, s
        return best

    @property
    def sources(self) -> list[str]:
        seen: list[str] = []
        for a in [self.primary, *self.siblings]:
            src = (getattr(a, "source", "") or "").lower()
            if src and src not in seen:
                seen.append(src)
        return seen

    @property
    def risk_assessment(self) -> RiskAssessment:
        """Lazy composite risk score (M11). Cached on first access."""
        cached = self.__dict__.get("_risk_cache")
        if cached is None:
            cached = score_group(self)
            self.__dict__["_risk_cache"] = cached
        return cached

    @property
    def risk_score(self) -> float:
        return self.risk_assessment.risk_score

    @property
    def urgency(self) -> str:
        return self.risk_assessment.urgency

    @property
    def timeline(self) -> CveTimeline:
        """Lazy timeline metrics (M13). Cached on first access."""
        cached = self.__dict__.get("_timeline_cache")
        if cached is None:
            cached = build_timeline(self)
            self.__dict__["_timeline_cache"] = cached
        return cached

    @property
    def ransomware_known(self) -> bool:
        return self.timeline.ransomware_known


def _primary_rank(alert) -> tuple:
    """Tiebreak so the richest alert in a group becomes the ``primary``.

    Preference order:
      1. NVD over KEV (NVD ships full CVSS vector + affected refs)
      2. Anything else over KEV
      3. Higher CVSS first
      4. Lexical source name as last-resort stable sort
    """
    src = (getattr(alert, "source", "") or "").lower()
    src_rank = {"nvd": 3, "ghsa": 2, "certfr": 2, "kev": 1}.get(src, 1)
    cvss = float(getattr(alert, "cvss_score", None) or 0.0)
    return (-src_rank, -cvss, src)
def group_alerts(alerts: Iterable) -> list[AlertGroup]:
    """Collapse iterables of Alert into AlertGroups, dedup'd by CVE id.

    Alerts without a CVE id stay as singleton groups keyed by
    ``"{source}:{external_id}"`` — they're vendor advisories or
    feed-specific bulletins that we render on their own card.

    The returned list is sorted by descending composite risk score
    (M11), with severity / CVSS / EPSS as tiebreakers and the key as
    final stable order.
    """
    buckets: dict[str, list] = {}
    for a in alerts:
        cve = _extract_cve_id(a)
        if cve:
            key = cve
        else:
            src = (getattr(a, "source", "") or "alert").lower()
            ext = (getattr(a, "external_id", "") or str(getattr(a, "id", ""))).strip()
            key = f"{src}:{ext}"
        buckets.setdefault(key, []).append(a)

    groups: list[AlertGroup] = []
    for key, items in buckets.items():
        items.sort(key=_primary_rank)
        groups.append(AlertGroup(key=key, primary=items[0], siblings=items[1:]))

    def _sort_key(g: AlertGroup):
        return (
            -g.risk_score,
            -_SEVERITY_ORDER.get(g.severity, 0),
            -(g.max_cvss or 0.0),
            -(g.max_epss or 0.0),
            g.key,
        )

    groups.sort(key=_sort_key)
    return groups
