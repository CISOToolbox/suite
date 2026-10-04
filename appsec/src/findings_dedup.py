"""Finding deduplication: insert or refresh findings based on dedup_key."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Finding


async def upsert_findings(
    db: AsyncSession,
    application_id: uuid.UUID,
    raw_findings: list[dict],
) -> dict[str, int]:
    stats = {"inserted": 0, "refreshed": 0, "reopened": 0, "silenced": 0}
    now = datetime.now(timezone.utc)
    legacy = await _plan_legacy_semgrep(db, application_id, raw_findings)

    for raw in raw_findings:
        dedup_key = raw.get("dedup_key", "")
        if not dedup_key:
            continue

        result = await db.execute(
            select(Finding).where(
                Finding.application_id == application_id,
                Finding.dedup_key == dedup_key,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            existing = legacy.get(dedup_key)
            if existing is not None:
                existing.dedup_key = dedup_key
                stats["rekeyed"] = stats.get("rekeyed", 0) + 1

        # The line moves even when the finding does not: refresh it whatever
        # the status, or the UI would keep pointing at where the code used to
        # be. Never touched before, because a moved line used to mean a brand
        # new row.
        if existing is not None and raw.get("target"):
            existing.target = raw["target"][:500]

        if existing is None:
            # Honour status from ignore_engine (false_positive) if present,
            # otherwise default to "new".
            initial_status = raw.get("status", "new")
            triage_notes = raw.get("triage_notes", "")
            db.add(Finding(
                id=uuid.uuid4(),
                application_id=application_id,
                scanner=raw.get("scanner", ""),
                type=raw.get("type", ""),
                severity=raw.get("severity", "info"),
                title=raw.get("title", "")[:500],
                description=raw.get("description", "")[:5000],
                target=raw.get("target", "")[:500],
                evidence=raw.get("evidence", {}),
                status=initial_status,
                dedup_key=dedup_key,
                cve_id=raw.get("cve_id"),
                triage_notes=triage_notes[:2000] if triage_notes else "",
                triaged_at=now if initial_status == "false_positive" else None,
                triaged_by="ignore-rule" if initial_status == "false_positive" else None,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            ))
            stats["inserted"] += 1
        elif existing.status == "new":
            existing.title = raw.get("title", existing.title)[:500]
            existing.description = raw.get("description", existing.description)[:5000]
            existing.severity = raw.get("severity", existing.severity)
            existing.evidence = raw.get("evidence", existing.evidence)
            existing.last_seen_at = now
            existing.updated_at = now
            # Apply ignore-rule status if the engine flagged this finding.
            if raw.get("status") == "false_positive":
                existing.status = "false_positive"
                existing.triage_notes = raw.get("triage_notes", "")[:2000]
                existing.triaged_at = now
                existing.triaged_by = "ignore-rule"
                stats["silenced"] += 1
            else:
                stats["refreshed"] += 1
        elif existing.status in ("false_positive", "to_fix", "derogated"):
            # derogated (FEAT-45): accepted for a bounded time, so a re-detection is
            # expected; the scheduler brings it back to to_fix when the derogation ends.
            existing.evidence = raw.get("evidence", existing.evidence)
            existing.last_seen_at = now
            stats["silenced"] += 1
        elif existing.status == "fixed":
            existing.status = "new"
            existing.title = raw.get("title", existing.title)[:500]
            existing.severity = raw.get("severity", existing.severity)
            existing.evidence = raw.get("evidence", existing.evidence)
            existing.last_seen_at = now
            existing.updated_at = now
            existing.triaged_at = None
            existing.triaged_by = None
            existing.triage_notes = ""
            stats["reopened"] += 1

    await db.flush()
    return stats


LEGACY_SAST_PREFIX = "semgrep|sast|"


async def _plan_legacy_semgrep(db: AsyncSession, application_id: uuid.UUID,
                               raw_findings: list[dict]) -> dict[str, Finding]:
    """New SAST key → the row that finding had under its Semgrep-era key.

    Semgrep-era findings were keyed `semgrep|sast|<file>|<rule>|<id><n>`, the
    id being Semgrep's fingerprint — the placeholder "requires login" in its
    OSS edition, so told apart by their order only. SAST findings (Opengrep) are keyed
    `sast|<file>|<rule>|<digest of the matched lines>`, the rule under its
    registry name — the one those former keys carry. To
    keep each one's status and links (measures, derogations, non-conformities)
    rather than closing it and opening a twin, the first scan carries each
    former row over — decided over the whole scan, never match by match:

      1. a match at the same place (file:line) as exactly one former row of
         its file and rule takes it;
      2. otherwise, only when the scan has a single match for that file and
         rule and a single former row is left, that match takes it.

    Anything else gets a new finding and the former row is closed by the
    scan: a guess could hand one finding's verdict to another, for good.

    Only rows still undecided are candidates: after the first SAST scan every
    former row is either carried over (its key is no longer a Semgrep-era one)
    or closed and marked (`migration_closed_at`), so a later scan can never
    hand a former verdict — a derogation, say — to code written since.
    """
    rows = (await db.execute(
        select(Finding).where(
            Finding.application_id == application_id,
            Finding.dedup_key.startswith(LEGACY_SAST_PREFIX, autoescape=True),
            Finding.migration_closed_at.is_(None),
            Finding.status != "fixed",
        )
    )).scalars().all()
    if not rows:
        return {}
    by_group: dict[str, list[Finding]] = {}
    for r in rows:
        by_group.setdefault(r.dedup_key.rsplit("|", 1)[0], []).append(r)

    raws: dict[str, list[dict]] = {}
    for raw in raw_findings:
        ev = raw.get("evidence") or {}
        if raw.get("scanner") != "sast" or not raw.get("dedup_key"):
            continue
        if not ev.get("file") or not ev.get("rule_id"):
            continue
        group = f"{LEGACY_SAST_PREFIX}{ev['file']}|{ev['rule_id']}".lower()
        if group in by_group:
            raws.setdefault(group, []).append(raw)
    keys = [r["dedup_key"] for group in raws.values() for r in group]
    known = set((await db.execute(
        select(Finding.dedup_key).where(Finding.application_id == application_id,
                                        Finding.dedup_key.in_(keys))
    )).scalars().all()) if keys else set()

    plan: dict[str, Finding] = {}
    for group, matches in raws.items():
        left = list(by_group[group])
        pending = [m for m in matches if m["dedup_key"] not in known]
        for m in list(pending):                         # 1. same place
            target = (m.get("target") or "")[:500]
            here = [r for r in left if r.target == target]
            if len(here) == 1:
                plan[m["dedup_key"]] = here[0]
                left.remove(here[0])
                pending.remove(m)
        if len(matches) == 1 and len(pending) == 1 and len(left) == 1:   # 2. sole one
            plan[pending[0]["dedup_key"]] = left[0]
    return plan
