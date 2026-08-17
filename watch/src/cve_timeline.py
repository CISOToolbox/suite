"""CVE timeline metrics + ransomware-campaign flag (M13).

A digest reader looking at a card has the abstract scoring (CVSS, EPSS,
KEV) but no sense of *time pressure* — "did CISA flag this last week,
or two years ago?". The two metrics below quantify that:

  * ``patch_lag_days`` — number of days between NVD publication and
    CISA adding the CVE to the KEV catalog. A small number means the
    vulnerability was weaponised quickly (vendor + CISA reacted within
    days); a large number means it sat dormant before being exploited.

  * ``exploit_window_days`` — best-effort estimate of the window
    between disclosure and active exploitation. When we don't have an
    EPSS time series we fall back to ``patch_lag_days`` because the
    KEV addition is the closest empirical proxy for "exploited in the
    wild" we have.

The ransomware flag is the CISA-curated ``knownRansomwareCampaignUse``
column on a KEV row ("Known" / "Unknown"). When present and set to
"Known", the CVE has been observed inside a ransomware campaign — a
much stronger urgency signal than KEV alone. The flag is read from the
KEV sibling's preserved ``raw_json`` payload — no schema migration
needed.

This module is pure computation over an :class:`AlertGroup` so it
unit-tests cleanly without a DB.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _to_utc(dt) -> datetime | None:
    """Best-effort coercion to a timezone-aware UTC datetime."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if isinstance(dt, str):
        try:
            d = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return None


def _find_sibling(group, source: str):
    """Return the first alert in ``group`` whose source matches."""
    src = source.lower()
    for a in [group.primary, *group.siblings]:
        if (getattr(a, "source", "") or "").lower() == src:
            return a
    return None


@dataclass(frozen=True)
class CveTimeline:
    """Timeline metrics for one AlertGroup. Self-explanatory dict export."""
    nvd_published: datetime | None
    kev_date_added: datetime | None
    patch_lag_days: int | None
    exploit_window_days: int | None
    ransomware_known: bool
    ransomware_label: str  # "Known" / "Unknown" / ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "nvd_published": self.nvd_published.isoformat() if self.nvd_published else "",
            "kev_date_added": self.kev_date_added.isoformat() if self.kev_date_added else "",
            "patch_lag_days": self.patch_lag_days,
            "exploit_window_days": self.exploit_window_days,
            "ransomware_known": self.ransomware_known,
            "ransomware_label": self.ransomware_label,
        }


def build_timeline(group) -> CveTimeline:
    """Compute the timeline for an :class:`AlertGroup`.

    The group's NVD sibling carries the real CVE publication date; the
    KEV sibling carries the CISA-added date (the ingester stores it in
    ``published_at`` since KEV rows have no separate publication
    timestamp). When the group is a singleton (CERT-FR with no CVE,
    e.g.) most fields stay ``None`` and the digest just doesn't render
    the timeline.
    """
    nvd = _find_sibling(group, "nvd")
    kev = _find_sibling(group, "kev")

    nvd_pub = _to_utc(getattr(nvd, "published_at", None)) if nvd else None
    # Fallback: even without a dedicated NVD sibling, the primary may be NVD-ish.
    if nvd_pub is None:
        nvd_pub = _to_utc(getattr(group.primary, "published_at", None))

    kev_added = _to_utc(getattr(kev, "published_at", None)) if kev else None

    patch_lag: int | None = None
    if nvd_pub and kev_added:
        delta = (kev_added - nvd_pub).days
        # Negative values can happen when feeds disagree on date precision
        # (one ships YYYY-MM-DD, the other a full timestamp). Floor to 0.
        patch_lag = max(0, delta)

    # Without an EPSS time-series we use the KEV gap as a proxy for the
    # exploit window. M14 could replace this with a real EPSS history.
    exploit_window = patch_lag

    ransomware_label = ""
    ransomware_known = False
    if kev is not None:
        raw = getattr(kev, "raw_json", None) or {}
        if isinstance(raw, dict):
            val = (raw.get("knownRansomwareCampaignUse") or "").strip()
            ransomware_label = val
            ransomware_known = val.lower() == "known"

    return CveTimeline(
        nvd_published=nvd_pub,
        kev_date_added=kev_added,
        patch_lag_days=patch_lag,
        exploit_window_days=exploit_window,
        ransomware_known=ransomware_known,
        ransomware_label=ransomware_label,
    )
