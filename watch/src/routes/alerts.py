"""Phase 3: alerts routes.

Visibility rule: a user sees an alert iff it has at least one
:class:`AlertMatch` whose ``scope_id`` belongs to a scope the user
owns or is a recipient of.

Endpoints:
  * GET    /api/alerts                — paginated list with filters.
  * GET    /api/alerts/{id}           — single alert + matches + status.
  * PATCH  /api/alerts/{id}/status    — update per-user triage status.
  * GET    /api/feeds                 — list feed states (admin or any logged-in user, read-only).
  * POST   /api/feeds/{source}/run    — manual ingestion trigger (admin-only).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import log_action
from src.auth import get_current_user, require_identity
from src.database import get_db
from src.models import (
    Alert, AlertAnalysis, AlertMatch, AlertStatus, FeedState, Scope, ScopeRecipient,
    User, WatchTarget,
)
from src.schemas import (
    AlertAnalysisResponse, AlertBulkStatusUpdate, AlertMatchResponse, AlertResponse,
    AlertStatusUpdate, FeedStateResponse,
)

router = APIRouter(prefix="/api", tags=["alerts"])


async def _user_scope_ids(db: AsyncSession, user: Optional[User]) -> set[uuid.UUID]:
    """Scopes the user can see (owner OR recipient by email).

    `user is None` means auth is disabled (see THE `None` CONTRACT in
    src/auth_common.py): there is no identity to filter on and the caller
    is admin, so every scope is visible.
    """
    if user is None:
        return set((await db.execute(select(Scope.id))).scalars().all())
    owned = (await db.execute(
        select(Scope.id).where(Scope.owner_id == user.id)
    )).scalars().all()
    shared = (await db.execute(
        select(ScopeRecipient.scope_id).where(
            ScopeRecipient.email == (user.email or "").lower()
        )
    )).scalars().all()
    return set(owned) | set(shared)


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    severity: Optional[str] = Query(None),
    scope_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None),
    kev_only: bool = Query(False),
    source: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=200, description="Free-text search on title, summary, external_id"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    visible = await _user_scope_ids(db, user)
    if not visible:
        return []

    # Pre-filter alert ids by the user's visible scopes via AlertMatch.
    match_q = select(AlertMatch.alert_id).where(AlertMatch.scope_id.in_(visible)).distinct()
    if scope_id is not None:
        if scope_id not in visible:
            raise HTTPException(status_code=403, detail="scope not visible")
        match_q = select(AlertMatch.alert_id).where(AlertMatch.scope_id == scope_id).distinct()
    alert_ids = (await db.execute(match_q)).scalars().all()
    if not alert_ids:
        return []

    q = select(Alert).where(Alert.id.in_(alert_ids))
    if severity:
        q = q.where(Alert.severity == severity.lower())
    if source:
        q = q.where(Alert.source == source.lower())
    if kev_only:
        q = q.where(Alert.kev_listed == True)  # noqa: E712
    # Free-text search — ILIKE on title, summary and external_id. We
    # split on whitespace and AND each token so multi-word queries
    # match all terms. 16K+ NVD rows make client-side filtering
    # impractical, so we push this into SQL.
    if search:
        terms = [t for t in search.strip().split() if t]
        for term in terms[:8]:  # cap term count to avoid runaway queries
            pat = f"%{term}%"
            q = q.where(
                or_(
                    Alert.title.ilike(pat),
                    Alert.summary.ilike(pat),
                    Alert.external_id.ilike(pat),
                )
            )
    q = q.order_by(Alert.published_at.desc().nullslast(), Alert.ingested_at.desc())
    q = q.offset(offset).limit(limit)
    alerts = (await db.execute(q)).scalars().all()
    if not alerts:
        return []

    # Hydrate status (per-user) + matches (with target+scope labels).
    # AlertStatus is keyed on a user id; with auth disabled there is none,
    # so every alert reads as untriaged.
    statuses = {} if user is None else {
        r.alert_id: r for r in (await db.execute(
            select(AlertStatus).where(
                AlertStatus.user_id == user.id,
                AlertStatus.alert_id.in_([a.id for a in alerts]),
            )
        )).scalars().all()
    }
    if status:
        # Filter post-hydration so "new" can also mean "no row yet".
        if status == "new":
            alerts = [a for a in alerts if a.id not in statuses
                      or (statuses[a.id].status == "new")]
        else:
            alerts = [a for a in alerts
                      if a.id in statuses and statuses[a.id].status == status]
    if not alerts:
        return []

    match_rows = (await db.execute(
        select(AlertMatch, WatchTarget.label, WatchTarget.value, WatchTarget.kind, Scope.name)
        .join(WatchTarget, WatchTarget.id == AlertMatch.target_id)
        .join(Scope, Scope.id == AlertMatch.scope_id)
        .where(
            AlertMatch.alert_id.in_([a.id for a in alerts]),
            AlertMatch.scope_id.in_(visible),
        )
    )).all()
    matches_by_alert: dict[uuid.UUID, list[AlertMatchResponse]] = {}
    for m, t_label, t_value, t_kind, s_name in match_rows:
        matches_by_alert.setdefault(m.alert_id, []).append(AlertMatchResponse(
            target_id=m.target_id,
            scope_id=m.scope_id,
            match_kind=m.match_kind,
            match_value=m.match_value,
            matched_at=m.matched_at,
            target_label=t_label or f"{t_kind}:{t_value}",
            scope_name=s_name,
        ))

    out: list[AlertResponse] = []
    for a in alerts:
        st = statuses.get(a.id)
        ar = AlertResponse(
            id=a.id,
            source=a.source,
            external_id=a.external_id,
            title=a.title,
            summary=a.summary,
            severity=a.severity,
            cvss_score=a.cvss_score,
            cvss_vector=a.cvss_vector,
            epss_score=a.epss_score,
            kev_listed=a.kev_listed,
            published_at=a.published_at,
            modified_at=a.modified_at,
            references_json=a.references_json or [],
            affected_json=a.affected_json or [],
            ingested_at=a.ingested_at,
            status=(st.status if st else "new"),
            note=(st.note if st else ""),
            matches=matches_by_alert.get(a.id, []),
        )
        out.append(ar)
    return out


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    visible = await _user_scope_ids(db, user)
    if not visible:
        raise HTTPException(status_code=404, detail="alert not found")

    # Visibility check via AlertMatch.
    seen = (await db.execute(
        select(func.count(AlertMatch.id)).where(
            AlertMatch.alert_id == alert_id,
            AlertMatch.scope_id.in_(visible),
        )
    )).scalar_one()
    if not seen:
        raise HTTPException(status_code=404, detail="alert not found")

    a = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="alert not found")

    status_row = None if user is None else (await db.execute(
        select(AlertStatus).where(AlertStatus.alert_id == a.id, AlertStatus.user_id == user.id)
    )).scalar_one_or_none()

    match_rows = (await db.execute(
        select(AlertMatch, WatchTarget.label, WatchTarget.value, WatchTarget.kind, Scope.name)
        .join(WatchTarget, WatchTarget.id == AlertMatch.target_id)
        .join(Scope, Scope.id == AlertMatch.scope_id)
        .where(AlertMatch.alert_id == a.id, AlertMatch.scope_id.in_(visible))
    )).all()

    matches = [AlertMatchResponse(
        target_id=m.target_id,
        scope_id=m.scope_id,
        match_kind=m.match_kind,
        match_value=m.match_value,
        matched_at=m.matched_at,
        target_label=t_label or f"{t_kind}:{t_value}",
        scope_name=s_name,
    ) for m, t_label, t_value, t_kind, s_name in match_rows]

    return AlertResponse(
        id=a.id, source=a.source, external_id=a.external_id, title=a.title,
        summary=a.summary, severity=a.severity, cvss_score=a.cvss_score,
        cvss_vector=a.cvss_vector, epss_score=a.epss_score, kev_listed=a.kev_listed,
        published_at=a.published_at, modified_at=a.modified_at,
        references_json=a.references_json or [], affected_json=a.affected_json or [],
        ingested_at=a.ingested_at,
        status=(status_row.status if status_row else "new"),
        note=(status_row.note if status_row else ""),
        matches=matches,
    )


@router.get("/alerts/{alert_id}/sbom-impact")
async def alert_sbom_impact(
    alert_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Phase 7: cross-reference the alert against the AppSec SBOM.

    Same visibility rule as the alert detail endpoint. The Watch
    backend acts as the trusted caller to AppSec — the end user only
    learns of impacts on applications they can already see through the
    Watch alert (Watch does not leak AppSec ACLs here; it just relays
    what AppSec returned about its own application inventory).
    """
    from src.appsec_client import sbom_impact

    visible = await _user_scope_ids(db, user)
    if not visible:
        raise HTTPException(status_code=404, detail="alert not found")

    a = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="alert not found")

    seen = (await db.execute(
        select(func.count(AlertMatch.id)).where(
            AlertMatch.alert_id == alert_id, AlertMatch.scope_id.in_(visible),
        )
    )).scalar_one()
    if not seen:
        raise HTTPException(status_code=404, detail="alert not found")

    cve_id = ""
    if a.source == "nvd" and (a.external_id or "").upper().startswith("CVE-"):
        cve_id = a.external_id.upper()
    affected = list(a.affected_json or [])
    return await sbom_impact(cve_id or None, affected)


@router.patch("/alerts/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: uuid.UUID,
    body: AlertStatusUpdate,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    visible = await _user_scope_ids(db, user)
    if not visible:
        raise HTTPException(status_code=404, detail="alert not found")

    a = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="alert not found")

    seen = (await db.execute(
        select(func.count(AlertMatch.id)).where(
            AlertMatch.alert_id == alert_id, AlertMatch.scope_id.in_(visible),
        )
    )).scalar_one()
    if not seen:
        raise HTTPException(status_code=404, detail="alert not found")

    # `alert_statuses.user_id` is half the primary key and a NOT NULL FK:
    # triage is inherently per-user, so this route needs a real identity.
    triager = require_identity(user)
    status_row = (await db.execute(
        select(AlertStatus).where(AlertStatus.alert_id == a.id, AlertStatus.user_id == triager.id)
    )).scalar_one_or_none()
    if status_row is None:
        status_row = AlertStatus(
            alert_id=a.id,
            user_id=triager.id,
            status=body.status,
            note=body.note or "",
            updated_at=datetime.now(timezone.utc),
        )
        db.add(status_row)
    else:
        status_row.status = body.status
        status_row.note = body.note or ""
        status_row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await log_action(db, user, request, "alert.status",
                     target=f"{a.source}:{a.external_id}",
                     details={"status": body.status})
    await db.commit()

    # Re-use get_alert's hydration logic for the response.
    return await get_alert(a.id, user=user, db=db)


@router.post("/alerts/bulk-status")
async def bulk_update_alert_status(
    body: AlertBulkStatusUpdate,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Apply the same per-user triage ``status`` to several alerts in one
    transaction. Visibility is enforced per id: an alert that doesn't
    intersect the caller's scopes is skipped silently (not 404'd), so a
    partially-visible selection still applies cleanly to the visible
    rows. Returns ``{updated, skipped}`` counts.
    """
    visible = await _user_scope_ids(db, user)
    if not visible:
        return {"updated": 0, "skipped": len(body.ids)}

    # Only keep alerts the user can actually see.
    visible_alert_ids = set((await db.execute(
        select(AlertMatch.alert_id).where(
            AlertMatch.alert_id.in_(body.ids),
            AlertMatch.scope_id.in_(visible),
        )
    )).scalars().all())

    if not visible_alert_ids:
        return {"updated": 0, "skipped": len(body.ids)}

    # Same per-user primary key as PATCH /alerts/{id}/status.
    triager = require_identity(user)
    existing = {
        row.alert_id: row for row in (await db.execute(
            select(AlertStatus).where(
                AlertStatus.alert_id.in_(visible_alert_ids),
                AlertStatus.user_id == triager.id,
            )
        )).scalars().all()
    }
    now = datetime.now(timezone.utc)
    note = body.note or ""
    for aid in visible_alert_ids:
        row = existing.get(aid)
        if row is None:
            db.add(AlertStatus(
                alert_id=aid, user_id=triager.id,
                status=body.status, note=note, updated_at=now,
            ))
        else:
            row.status = body.status
            row.note = note
            row.updated_at = now
    await db.commit()
    await log_action(db, user, request, "alert.bulk_status",
                     target=f"{len(visible_alert_ids)} alerts",
                     details={"status": body.status, "count": len(visible_alert_ids)})
    await db.commit()
    return {
        "updated": len(visible_alert_ids),
        "skipped": len(body.ids) - len(visible_alert_ids),
        "status": body.status,
    }


# ── LLM analysis (Phase 4) ───────────────────────────────────────

async def _ensure_alert_visible(db: AsyncSession, user: Optional[User], alert_id: uuid.UUID) -> Alert:
    visible = await _user_scope_ids(db, user)
    if not visible:
        raise HTTPException(status_code=404, detail="alert not found")
    seen = (await db.execute(
        select(func.count(AlertMatch.id)).where(
            AlertMatch.alert_id == alert_id, AlertMatch.scope_id.in_(visible)
        )
    )).scalar_one()
    if not seen:
        raise HTTPException(status_code=404, detail="alert not found")
    a = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="alert not found")
    return a


@router.get("/alerts/{alert_id}/analysis", response_model=AlertAnalysisResponse | None)
async def get_alert_analysis(
    alert_id: uuid.UUID,
    language: Optional[str] = Query(None, pattern="^(fr|en)$"),
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    a = await _ensure_alert_visible(db, user, alert_id)
    from src.analysis import compute_alert_hash
    h = compute_alert_hash(a)
    lang = language or "fr"
    # Try the requested language first; fall back to any cached row so
    # an existing EN analysis still shows up if the user toggles locale
    # before regenerating.
    row = (await db.execute(
        select(AlertAnalysis).where(
            AlertAnalysis.alert_id == a.id,
            AlertAnalysis.content_hash == h,
            AlertAnalysis.language == lang,
        )
    )).scalar_one_or_none()
    if row is None:
        row = (await db.execute(
            select(AlertAnalysis).where(
                AlertAnalysis.alert_id == a.id,
                AlertAnalysis.content_hash == h,
            )
        )).scalar_one_or_none()
    if not row:
        return None
    return AlertAnalysisResponse.model_validate(row)


@router.post("/alerts/{alert_id}/analyze", response_model=AlertAnalysisResponse)
async def analyze_alert(
    alert_id: uuid.UUID,
    request: Request,
    language: Optional[str] = Query(None, pattern="^(fr|en)$"),
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    a = await _ensure_alert_visible(db, user, alert_id)
    # AI gate: same as ai_complete — only users granted ai_enabled may
    # trigger an LLM call. Managed-mode keys live on Pilot.
    if user is not None and (user.ai_enabled or "").lower() != "true":
        raise HTTPException(status_code=403, detail="AI access not granted")
    # Default to FR (the toolbox default locale). The frontend always
    # passes the active locale; this fallback only kicks in for API
    # callers that omit the param.
    lang = language or "fr"
    from src.analysis import generate_or_get
    row = await generate_or_get(db, a, user, language=lang)
    await log_action(db, user, request, "alert.analyze",
                     target=f"{a.source}:{a.external_id}",
                     details={"provider": row.provider, "model": row.model, "language": lang})
    await db.commit()
    return AlertAnalysisResponse.model_validate(row)


# ── Feed state (read-only for users, admin trigger) ──────────────

@router.get("/feeds", response_model=list[FeedStateResponse])
async def list_feeds(
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(FeedState).order_by(FeedState.source)
    )).scalars().all()
    # Cumulative totals per source — the per-run items_seen/items_new
    # columns get overwritten every tick, so users need an absolute
    # number to know whether a feed is actually populating the DB.
    totals_raw = (await db.execute(
        select(Alert.source, func.count(Alert.id)).group_by(Alert.source)
    )).all()
    totals = {src: int(cnt) for src, cnt in totals_raw}
    out: list[FeedStateResponse] = []
    for r in rows:
        resp = FeedStateResponse.model_validate(r)
        resp.total_in_db = totals.get(r.source, 0)
        out.append(resp)
    return out


@router.post("/feeds/{source}/run")
async def run_feed_now(
    source: str,
    request: Request,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # user is None => auth disabled => admin by contract.
    if user is not None and (user.role or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    from src.scheduler import trigger_now
    result = await trigger_now(source)
    await log_action(db, user, request, "feed.run", target=source, details=result)
    await db.commit()
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "unknown"))
    return result
