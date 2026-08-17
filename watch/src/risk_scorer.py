"""Composite risk scoring for alert groups.

CVSS, EPSS, and KEV in isolation each miss something. CVSS is the
paper-severity (theoretical impact), EPSS is the probabilistic
exploitability over the next 30 days, KEV is the empirical "we've seen
this exploited in the wild" signal. A user triaging a digest wants ONE
number — `0..100` — that aggregates all three, plus a verbal urgency
("PATCH IMMEDIATELY" vs. "next maintenance cycle") so the digest cards
sort by what to act on first, not by what the vendor labeled as
critical.

The formula is a straight port of the open-source `cve-mcp-server`
risk_scorer (MIT licensed), adapted to operate on a Watch
:class:`AlertGroup` instead of raw NVD/EPSS/KEV dicts:

  * `cvss_contribution`  = (cvss / 10) · 20      → 0..20
  * `epss_contribution`  = epss · 100 · 0.35     → 0..35
  * `kev_contribution`   = 30 if KEV-listed      → 0|30
  * `poc_contribution`   = 0..15 by confidence   → 0..15 (M12 — not used yet)

  base = sum of contributions

Then three boost multipliers stack:

  * KEV + PoC (any confidence)               → ×1.15
  * CVSS ≥ 9.0 and EPSS > 0.7                → ×1.10
  * Published ≤ 7 days ago                   → ×1.05

`risk_score = min(100, round(base · multiplier, 2))`. The four
`risk_label` thresholds (≤25 LOW, ≤50 MEDIUM, ≤75 HIGH, else CRITICAL)
and the urgency ladder are exactly the upstream defaults.

PoC enrichment is a separate milestone (M12: GitHub/Nuclei/ExploitDB
lookup). Until then `score_group` accepts `poc_confidence="NONE"` and
the PoC-related boost stays inert.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


_POC_SCORES = {
    "WEAPONIZED": 15,
    "PUBLIC_EXPLOIT_REMOTE": 12,
    "PUBLIC_EXPLOIT": 10,
    "PUBLIC_POC_HIGH_QUALITY": 7,
    "PUBLIC_POC_LOW_QUALITY": 3,
    "NONE": 0,
}


@dataclass(frozen=True)
class RiskAssessment:
    """Result of scoring one AlertGroup.

    The dict-style export (``as_dict()``) is what the digest renderer
    and the unit tests consume; the dataclass shape keeps callers
    typed.
    """
    risk_score: float
    risk_label: str
    urgency: str
    cvss_score: float
    epss_probability: float
    in_kev: bool
    poc_confidence: str
    cvss_contribution: float
    epss_contribution: float
    kev_contribution: float
    poc_contribution: float
    boosters_applied: tuple[str, ...]
    days_since_published: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "urgency": self.urgency,
            "components": {
                "cvss_score": self.cvss_score,
                "epss_probability": self.epss_probability,
                "in_kev": self.in_kev,
                "poc_confidence": self.poc_confidence,
                "cvss_contribution": self.cvss_contribution,
                "epss_contribution": self.epss_contribution,
                "kev_contribution": self.kev_contribution,
                "poc_contribution": self.poc_contribution,
            },
            "boosters_applied": list(self.boosters_applied),
            "days_since_published": self.days_since_published,
        }


def _label_for(score: float) -> str:
    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def _urgency_for(in_kev: bool, epss: float, cvss: float) -> str:
    if in_kev and epss > 0.5:
        return "PATCH_IMMEDIATELY"
    if in_kev:
        return "PATCH_WITHIN_24H"
    if epss > 0.5:
        return "PATCH_WITHIN_72H"
    if cvss >= 9.0:
        return "PATCH_THIS_WEEK"
    if cvss >= 7.0:
        return "PATCH_THIS_MONTH"
    return "NEXT_CYCLE"


def _days_since(published_at) -> int | None:
    if published_at is None:
        return None
    if isinstance(published_at, str):
        # Best-effort ISO parse — tolerate trailing Z.
        try:
            dt = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        except ValueError:
            return None
    elif isinstance(published_at, datetime):
        dt = published_at
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)


def score_group(
    group,
    poc_confidence: str = "NONE",
) -> RiskAssessment:
    """Compute the composite risk for an :class:`AlertGroup`.

    ``group`` must expose ``max_cvss``, ``max_epss``, ``kev_listed``
    and ``primary`` (an Alert-like object with a ``published_at``
    attribute). ``poc_confidence`` is the placeholder for the
    upcoming M12 PoC lookup — pass ``"NONE"`` until then.
    """
    cvss = float(group.max_cvss or 0.0)
    epss = float(group.max_epss or 0.0)
    in_kev = bool(group.kev_listed)
    if poc_confidence not in _POC_SCORES:
        poc_confidence = "NONE"

    cvss_c = (cvss / 10.0) * 20.0
    epss_c = epss * 100.0 * 0.35
    kev_c = 30.0 if in_kev else 0.0
    poc_c = float(_POC_SCORES[poc_confidence])
    base = cvss_c + epss_c + kev_c + poc_c

    multiplier = 1.0
    boosters: list[str] = []

    if in_kev and poc_confidence != "NONE":
        multiplier *= 1.15
        boosters.append("KEV+PoC")
    if cvss >= 9.0 and epss > 0.7:
        multiplier *= 1.10
        boosters.append("CVSS>=9+EPSS>0.7")

    published_at = getattr(group.primary, "published_at", None)
    days = _days_since(published_at)
    if days is not None and days <= 7:
        multiplier *= 1.05
        boosters.append("Published<=7days")

    score = min(100.0, round(base * multiplier, 2))

    return RiskAssessment(
        risk_score=score,
        risk_label=_label_for(score),
        urgency=_urgency_for(in_kev, epss, cvss),
        cvss_score=cvss,
        epss_probability=epss,
        in_kev=in_kev,
        poc_confidence=poc_confidence,
        cvss_contribution=round(cvss_c, 2),
        epss_contribution=round(epss_c, 2),
        kev_contribution=kev_c,
        poc_contribution=poc_c,
        boosters_applied=tuple(boosters),
        days_since_published=days,
    )
