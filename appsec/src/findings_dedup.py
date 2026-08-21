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
        elif existing.status in ("false_positive", "to_fix"):
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
