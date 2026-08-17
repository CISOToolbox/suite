"""Phase 5 (option A — per-scope digest): preview + history.

Digest preferences are stored on the Scope itself (see ScopeUpdate /
ScopeResponse in src.schemas). The two endpoints that remain here are:

  * GET /api/digest/preview     — render *now* what would be sent for the
                                  visible scopes of the logged-in user.
  * GET /api/digest/runs        — list of past DigestRun rows visible to
                                  the user (their own + their owned
                                  scopes' runs).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.database import get_db
from src.digest import (
    _alerts_for_scope,
    _render_threat_brief,
    _user_scopes,
    force_send_digest_for_scope,
    render_html,
    tick_digests,
)
from src.digest_grouping import group_alerts
from src.models import DigestRun, Scope, User

router = APIRouter(prefix="/api/digest", tags=["digest"])


class DigestRunResponse(BaseModel):
    id: uuid.UUID
    user_email: str
    scope_id: uuid.UUID
    kind: str
    calendar_date: str
    sent_at: datetime
    status: str
    alerts_count: int
    error_message: str
    model_config = {"from_attributes": True}


class DigestSendResponse(BaseModel):
    sent: int
    failed: int
    recipients: list[str]


@router.get("/preview", response_class=HTMLResponse)
async def preview_digest(
    scope_id: Optional[uuid.UUID] = None,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scopes = await _user_scopes(db, user)
    if scope_id is not None:
        scopes = [s for s in scopes if s.id == scope_id]
        if not scopes:
            raise HTTPException(status_code=404, detail="scope not found or not visible")
    if not scopes:
        return HTMLResponse("<p>No scopes — nothing to preview.</p>")
    since = datetime.now(timezone.utc) - timedelta(days=1)
    parts: list[str] = []
    for scope in scopes:
        alerts = await _alerts_for_scope(db, user, scope, since)
        groups = group_alerts(alerts)
        # Threat brief: only call Claude+web_search when the scope has an
        # explicit prompt; otherwise the preview renders a friendly
        # placeholder. Generating the brief on preview matches the actual
        # send behaviour so a CISO can validate the prompt without waiting
        # for the scheduled cadence.
        if (getattr(scope, "threat_prompt", "") or "").strip():
            brief_html, citations = await _render_threat_brief(
                db, scope, since, language="fr",
            )
        else:
            brief_html, citations = "", []
        # Preview skips LLM analyses on vuln cards (expensive, on-demand);
        # render_html falls back to the raw advisory summary when a group
        # has no entry.
        parts.append(render_html(
            scope.name, groups, {},
            threat_brief_html=brief_html,
            threat_citations=citations,
            user_name=(user.name or "") if user else "", since=since,
            language="fr",
        ))
    return HTMLResponse("<hr/>".join(parts))


@router.post("/run-now")
async def run_digests_now(
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force a digest tick immediately. Admin-only. Used to validate the
    SMTP wiring without waiting for the next scheduler tick (default 15 min).

    Only scopes whose ``_is_due`` window matches the current minute fire —
    this is NOT a bypass for the time-of-day rule, it just skips the
    scheduler's sleep. To re-send a digest already stamped for today,
    delete the matching ``digest_runs`` row first.
    """
    # user is None => auth disabled => admin by contract.
    if user is not None and (user.role or "") != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    sent = await tick_digests(db)
    return {"ok": True, "sent": sent}


@router.get("/runs", response_model=list[DigestRunResponse])
async def list_runs(
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # User sees runs targeted at them OR for scopes they own. With auth
    # disabled there is no "them" and the caller is admin: show every run.
    if user is None:
        rows = (await db.execute(
            select(DigestRun).order_by(DigestRun.sent_at.desc()).limit(100)
        )).scalars().all()
    else:
        own_scope_ids = (await db.execute(
            select(Scope.id).where(Scope.owner_id == user.id)
        )).scalars().all()
        rows = (await db.execute(
            select(DigestRun).where(
                (DigestRun.user_email == (user.email or "").lower())
                | (DigestRun.scope_id.in_(own_scope_ids) if own_scope_ids else False)
            ).order_by(DigestRun.sent_at.desc()).limit(100)
        )).scalars().all()
    return [DigestRunResponse.model_validate(r) for r in rows]


@router.get("/runs/{run_id}/body", response_class=HTMLResponse)
async def get_run_body(
    run_id: uuid.UUID,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the HTML body of a past digest run for in-app replay.

    Visibility mirrors :func:`list_runs`: the requester must be the
    recipient or own the scope. Body is served as ``text/html`` so the
    frontend can drop it straight into an ``<iframe srcdoc>``.
    """
    row = (await db.execute(
        select(DigestRun).where(DigestRun.id == run_id)
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="run not found")
    # Auth disabled: no identity to match, and the caller is admin.
    is_recipient = user is None or (row.user_email or "").lower() == (user.email or "").lower()
    is_owner = False
    if not is_recipient:
        scope = (await db.execute(
            select(Scope).where(Scope.id == row.scope_id)
        )).scalar_one_or_none()
        is_owner = bool(user is not None and scope and scope.owner_id == user.id)
    if not (is_recipient or is_owner):
        raise HTTPException(status_code=403, detail="forbidden")
    body = row.body_html or ""
    if not body.strip():
        body = (
            "<p style='padding:24px;color:#888;font-family:sans-serif'>"
            "Aucun contenu archivé pour ce digest "
            "(envoi antérieur à la migration 013 ou statut non terminal)."
            "</p>"
        )
    return HTMLResponse(body)


@router.post("/scopes/{scope_id}/send", response_model=DigestSendResponse)
async def force_send_for_scope(
    scope_id: uuid.UUID,
    kind: str,
    user: Optional[User] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force-send the requested digest kind (``vuln`` or ``threat``) for
    a scope NOW, bypassing schedule and per-day idempotency.

    Admin only — sending costs SMTP + LLM tokens and replays already-sent
    emails. Existing terminal ``DigestRun`` rows for today are deleted so
    the new send is recorded cleanly.
    """
    require_admin(user)
    if kind not in ("vuln", "threat"):
        raise HTTPException(status_code=400, detail="kind must be 'vuln' or 'threat'")
    scope = (await db.execute(
        select(Scope).where(Scope.id == scope_id)
    )).scalar_one_or_none()
    if scope is None:
        raise HTTPException(status_code=404, detail="scope not found")
    try:
        result = await force_send_digest_for_scope(db, scope, kind)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return DigestSendResponse(**result)
