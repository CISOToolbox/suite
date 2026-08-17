"""Match newly ingested alerts against enabled WatchTargets.

The matcher runs after each feed adapter cycle and produces one
:class:`AlertMatch` row per (alert, target) pair that satisfies:

  * CPE alerts → target.kind == "cpe" AND CPE wildcards align
    AND (no version_constraint OR the version is in the constraint).
  * PURL alerts → target.kind == "purl" AND the same package
    (case-insensitive type+name match) AND version satisfies the
    target.version_constraint.
  * Keyword alerts (and generic alerts) → target.kind == "keyword"
    AND the keyword appears in the alert title/summary/affected
    vendor+product (case-insensitive substring).
  * KEV alerts → emit matches against CPE targets when vendor/product
    fragments match, AND set ``kev_listed`` on the corresponding NVD
    alert row if one already exists (post-ingest merge).

The function is intentionally pure-Python — no LLM, no network. It
runs inside the scheduler's per-source lock so we can rely on the
database snapshot it sees being consistent.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Iterable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Alert, AlertMatch, WatchTarget

logger = logging.getLogger("watch-matcher")


async def match_alert(db: AsyncSession, alert: Alert) -> list[AlertMatch]:
    """Compute and persist :class:`AlertMatch` rows for ``alert``.

    Returns the freshly-created rows. Existing matches (same
    alert_id+target_id pair) are skipped — uniqueness is enforced
    by the database constraint anyway.
    """
    # Pre-load enabled targets once per alert. Watch deployments are
    # small enough that loading the full set is cheaper than indexing
    # every dimension we'd want to filter on.
    rows = (await db.execute(
        select(WatchTarget).where(WatchTarget.enabled == True)  # noqa: E712
    )).scalars().all()
    if not rows:
        return []

    matches: list[AlertMatch] = []
    seen_target_ids: set[uuid.UUID] = set()

    # Index existing matches so we don't re-create them on a re-ingest.
    existing = (await db.execute(
        select(AlertMatch.target_id).where(AlertMatch.alert_id == alert.id)
    )).scalars().all()
    seen_target_ids.update(existing)

    for target in rows:
        if target.id in seen_target_ids:
            continue
        match_value = _target_matches_alert(target, alert)
        if not match_value:
            continue
        m = AlertMatch(
            id=uuid.uuid4(),
            alert_id=alert.id,
            target_id=target.id,
            scope_id=target.scope_id,
            match_kind=target.kind,
            match_value=match_value[:500],
            matched_at=datetime.now(timezone.utc),
        )
        db.add(m)
        matches.append(m)
        seen_target_ids.add(target.id)

    if matches:
        await db.flush()
    return matches


async def match_target(db: AsyncSession, target: WatchTarget, limit: int = 5000) -> list[AlertMatch]:
    """Backfill matches for a newly created/enabled target against the
    most-recently-ingested ``limit`` alerts.

    Used by the create/enable target route so the user doesn't wait
    until the next feed cycle to see hits. The limit caps the scan to
    avoid pathological cases when a large NVD backfill ran the week
    before. Matches are stamped ``match_kind="backfill"`` so digests can
    exclude them (they surface historical CVEs, not news) while the app
    still lists them for the initial triage; KEV-listed ones are the
    exception and do reach the digest (see digest_filter).
    """
    from sqlalchemy import select as _sel
    rows = (await db.execute(
        _sel(Alert).order_by(Alert.published_at.desc().nullslast(),
                              Alert.ingested_at.desc()).limit(limit)
    )).scalars().all()
    if not rows:
        return []

    existing = set((await db.execute(
        select(AlertMatch.alert_id).where(AlertMatch.target_id == target.id)
    )).scalars().all())

    created: list[AlertMatch] = []
    for a in rows:
        if a.id in existing:
            continue
        v = _target_matches_alert(target, a)
        if not v:
            continue
        m = AlertMatch(
            id=uuid.uuid4(),
            alert_id=a.id,
            target_id=target.id,
            scope_id=target.scope_id,
            match_kind="backfill",
            match_value=v[:500],
            matched_at=datetime.now(timezone.utc),
        )
        db.add(m)
        created.append(m)
    if created:
        await db.flush()
    return created


def _target_matches_alert(target: WatchTarget, alert: Alert) -> str:
    """Return the matched value (for AlertMatch.match_value) or ``""``."""
    affected = alert.affected_json or []

    if target.kind == "cpe":
        return _match_cpe(target, affected)
    if target.kind == "purl":
        return _match_purl(target, affected)
    if target.kind == "keyword":
        return _match_keyword(target, alert, affected)
    return ""


# ── CPE matching ─────────────────────────────────────────────────

# cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:
#   <language>:<sw_edition>:<target_sw>:<target_hw>:<other>
def _split_cpe(cpe: str) -> list[str]:
    parts = cpe.split(":")
    # Pad to 13 to tolerate truncated forms.
    while len(parts) < 13:
        parts.append("*")
    return parts


def _match_cpe(target: WatchTarget, affected: list[dict]) -> str:
    t_parts = _split_cpe(target.value.lower())
    if len(t_parts) < 5 or not target.value.lower().startswith("cpe:2.3:"):
        return ""

    for entry in affected:
        cpe = (entry.get("cpe") or "").lower()
        if not cpe:
            continue
        a_parts = _split_cpe(cpe)
        # Compare part / vendor / product (positions 2/3/4).
        if not _cpe_field_matches(t_parts[2], a_parts[2]):
            continue
        if not _cpe_field_matches(t_parts[3], a_parts[3]):
            continue
        if not _cpe_field_matches(t_parts[4], a_parts[4]):
            continue
        # Version constraint check (target wins over alert range).
        if target.version_constraint:
            advisory_range = entry.get("version_range", "") or ""
            if not _version_constraint_intersects(target.version_constraint, advisory_range):
                continue
        return cpe
    return ""


def _cpe_field_matches(target_field: str, alert_field: str) -> bool:
    if target_field in ("*", "") or alert_field in ("*", ""):
        return True
    return target_field == alert_field


# ── PURL matching ────────────────────────────────────────────────

_PURL_RX = re.compile(r"^pkg:([^/]+)/(.+?)(?:@(.+))?$", re.IGNORECASE)


def _parse_purl(purl: str) -> tuple[str, str] | None:
    m = _PURL_RX.match((purl or "").strip())
    if not m:
        return None
    return m.group(1).lower(), m.group(2).lower()


def _match_purl(target: WatchTarget, affected: list[dict]) -> str:
    t_parsed = _parse_purl(target.value)
    if not t_parsed:
        return ""
    t_type, t_name = t_parsed
    for entry in affected:
        purl = entry.get("purl") or ""
        a_parsed = _parse_purl(purl)
        if not a_parsed:
            continue
        if a_parsed != (t_type, t_name):
            continue
        if target.version_constraint:
            if not _version_constraint_intersects(
                target.version_constraint, entry.get("version_range", "") or ""
            ):
                continue
        return purl
    return ""


# ── Keyword matching ─────────────────────────────────────────────

def _match_keyword(target: WatchTarget, alert: Alert, affected: list[dict]) -> str:
    kw = (target.value or "").strip().lower()
    if not kw:
        return ""

    haystacks: list[str] = []
    haystacks.append((alert.title or "").lower())
    haystacks.append((alert.summary or "").lower())
    for entry in affected:
        for field in ("vendor", "product", "keyword_hint", "cpe", "purl"):
            val = entry.get(field)
            if val:
                haystacks.append(str(val).lower())

    for h in haystacks:
        if kw in h:
            return kw
    return ""


# ── Version constraint intersection ──────────────────────────────

_RANGE_TOKEN = re.compile(r"\s*(<=|>=|<|>|==|=)?\s*([^,;\s]+)")


def _to_specifier(constraint: str) -> SpecifierSet | None:
    """Convert "<3.0.0", ">=1.0,<2.0" into a packaging SpecifierSet.

    Returns ``None`` if the string is empty or unparseable — the
    caller treats that as "no constraint".
    """
    c = (constraint or "").strip()
    if not c or c == "*":
        return None
    # Normalise: packaging requires SemVer-ish ops; we accept "=" as "==".
    bits: list[str] = []
    for op, ver in _RANGE_TOKEN.findall(c):
        if not ver:
            continue
        op = op or "=="
        if op == "=":
            op = "=="
        bits.append(f"{op}{ver}")
    if not bits:
        return None
    try:
        return SpecifierSet(",".join(bits))
    except InvalidSpecifier:
        return None


def _version_constraint_intersects(target_constraint: str, advisory_range: str) -> bool:
    """True if the target's constraint shares at least one version with the advisory's range.

    Implementation: probe sample boundary versions from the advisory's
    range against the target's specifier. This is approximate but
    sufficient for triage; the LLM analysis step refines edge cases.
    """
    t_spec = _to_specifier(target_constraint)
    if t_spec is None:
        # Target accepts every version → if advisory has any range, match.
        return True

    a_spec = _to_specifier(advisory_range)
    if a_spec is None:
        # Advisory affects all versions → target's narrower window still
        # overlaps (since target is non-empty by definition).
        return True

    # Sample boundary versions extracted from both constraints.
    probes = sorted({
        v
        for v in list(_extract_boundary_versions(target_constraint))
                 + list(_extract_boundary_versions(advisory_range))
    })
    for v in probes:
        try:
            ver = Version(v)
        except InvalidVersion:
            continue
        if ver in t_spec and ver in a_spec:
            return True
    return False


def _extract_boundary_versions(constraint: str) -> Iterable[str]:
    for _, ver in _RANGE_TOKEN.findall(constraint or ""):
        if ver:
            yield ver
