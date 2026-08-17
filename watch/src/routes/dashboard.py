"""Phase 6: dashboard KPIs.

Computes a user-scoped overview of the Watch state:
  * counters: scopes, targets (enabled), open alerts, KEV-flagged alerts,
    critical+high in the last 30d, alerts unacknowledged
  * severity breakdown (donut): count per severity over the visible set
  * source breakdown: count per feed source over the visible set
  * recent KEV/critical alerts (top 10) for the at-a-glance list

The same visibility rule as /api/alerts applies — a user only sees
KPIs aggregated over the scopes they own or receive.

This endpoint is read-only and cheap (a handful of indexed queries);
the panel can be polled or refreshed on demand without rate-limiting.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import (
    Alert, AlertMatch, AlertStatus, Scope, ScopeRecipient, User, WatchTarget,
)
from src.routes.alerts import _user_scope_ids

router = APIRouter(prefix="/api", tags=["dashboard"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


@router.get("/dashboard")
async def dashboard(
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    visible = await _user_scope_ids(db, user)
    if not visible:
        return _empty_payload()

    now = datetime.now(timezone.utc)
    cutoff_30d = now - timedelta(days=30)
    cutoff_7d = now - timedelta(days=7)

    # ── Scopes / targets counters
    # `user is None` = auth disabled = admin over the whole instance: every
    # scope counts as owned, nothing is "shared with me" (no me).
    if user is None:
        owned_count = (await db.execute(select(func.count(Scope.id)))).scalar_one()
        shared_count = 0
    else:
        owned_count = (await db.execute(
            select(func.count(Scope.id)).where(Scope.owner_id == user.id)
        )).scalar_one()
        shared_count = (await db.execute(
            select(func.count(ScopeRecipient.scope_id)).where(
                ScopeRecipient.email == (user.email or "").lower()
            )
        )).scalar_one()
    targets_enabled = (await db.execute(
        select(func.count(WatchTarget.id)).where(
            WatchTarget.scope_id.in_(visible),
            WatchTarget.enabled == True,  # noqa: E712
        )
    )).scalar_one()

    # ── Visible alert ids (one query, reused below)
    alert_ids = [r for r in (await db.execute(
        select(distinct(AlertMatch.alert_id)).where(
            AlertMatch.scope_id.in_(visible)
        )
    )).scalars().all()]
    if not alert_ids:
        return _empty_payload(scopes_owned=owned_count, scopes_shared=shared_count,
                              targets_enabled=targets_enabled)

    total_alerts = len(alert_ids)

    # ── KEV + critical/high counters
    kev_count = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.id.in_(alert_ids),
            Alert.kev_listed == True,  # noqa: E712
        )
    )).scalar_one()
    crit_high_30d = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.id.in_(alert_ids),
            Alert.severity.in_(["critical", "high"]),
            Alert.published_at >= cutoff_30d,
        )
    )).scalar_one()

    # ── Unacknowledged count (alerts with no AlertStatus row for this user,
    #     or status="new")
    # Triage is per-user; with no identity every alert reads as untriaged.
    statuses = {} if user is None else {
        r.alert_id: r.status
        for r in (await db.execute(
            select(AlertStatus).where(
                AlertStatus.user_id == user.id,
                AlertStatus.alert_id.in_(alert_ids),
            )
        )).scalars().all()
    }
    new_count = sum(1 for aid in alert_ids if statuses.get(aid, "new") == "new")

    # ── Severity breakdown
    sev_rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.id.in_(alert_ids))
        .group_by(Alert.severity)
    )).all()
    sev_map = {row[0] or "unknown": row[1] for row in sev_rows}
    severity_breakdown = [
        {"label": s, "value": int(sev_map.get(s, 0))}
        for s in SEVERITY_ORDER if sev_map.get(s, 0) > 0
    ]

    # ── Source breakdown
    src_rows = (await db.execute(
        select(Alert.source, func.count(Alert.id))
        .where(Alert.id.in_(alert_ids))
        .group_by(Alert.source)
        .order_by(func.count(Alert.id).desc())
    )).all()
    source_breakdown = [
        {"label": row[0], "value": int(row[1])} for row in src_rows
    ]

    # ── Recent KEV / critical (top 10 by published_at desc, last 7d)
    recent_rows = (await db.execute(
        select(Alert)
        .where(
            Alert.id.in_(alert_ids),
            (Alert.kev_listed == True) | (Alert.severity.in_(["critical", "high"])),  # noqa: E712
            Alert.published_at >= cutoff_7d,
        )
        .order_by(Alert.kev_listed.desc(), Alert.published_at.desc().nullslast())
        .limit(10)
    )).scalars().all()
    recent_alerts = [
        {
            "id": str(a.id),
            "source": a.source,
            "external_id": a.external_id,
            "title": a.title,
            "severity": a.severity or "unknown",
            "cvss_score": a.cvss_score,
            "kev_listed": bool(a.kev_listed),
            "published_at": a.published_at.isoformat() if a.published_at else None,
        }
        for a in recent_rows
    ]

    return {
        "scopes_owned": int(owned_count),
        "scopes_shared": int(shared_count),
        "targets_enabled": int(targets_enabled),
        "alerts_total": int(total_alerts),
        "alerts_kev": int(kev_count),
        "alerts_crit_high_30d": int(crit_high_30d),
        "alerts_new": int(new_count),
        "severity_breakdown": severity_breakdown,
        "source_breakdown": source_breakdown,
        "recent_alerts": recent_alerts,
    }


def _empty_payload(scopes_owned: int = 0, scopes_shared: int = 0,
                   targets_enabled: int = 0) -> dict:
    return {
        "scopes_owned": int(scopes_owned),
        "scopes_shared": int(scopes_shared),
        "targets_enabled": int(targets_enabled),
        "alerts_total": 0,
        "alerts_kev": 0,
        "alerts_crit_high_30d": 0,
        "alerts_new": 0,
        "severity_breakdown": [],
        "source_breakdown": [],
        "recent_alerts": [],
    }
