from __future__ import annotations

import uuid

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import log_action
from src.auth import get_current_user, require_admin
from src.database import get_db
from src.models import Application, ScanJob, User
from src.schemas import ScanJobResponse

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("")
async def list_scans(
    app_id: uuid.UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(ScanJob).order_by(ScanJob.created_at.desc())
    if app_id:
        query = query.where(ScanJob.application_id == app_id)

    result = await db.execute(query.offset(offset).limit(limit))
    jobs = result.scalars().all()

    app_ids = list(set(j.application_id for j in jobs))
    app_names = {}
    if app_ids:
        apps_q = await db.execute(select(Application.id, Application.name).where(Application.id.in_(app_ids)))
        app_names = {row[0]: row[1] for row in apps_q}

    items = []
    for j in jobs:
        d = ScanJobResponse.model_validate(j).model_dump()
        d["application_name"] = app_names.get(j.application_id, "")
        items.append(d)
    return items


@router.post("/reset")
async def reset_all_stuck_scans(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force every ``running``/``pending`` scan job across **all** apps
    to ``failed``. Use when many apps are stuck simultaneously
    (multi-app disaster, post-migration aftermath) and resetting one
    by one would take too long.

    Admin-only. The scheduler's boot sweep already runs this implicitly
    on startup; this endpoint is for cases where restarting the
    container is undesirable.
    """
    require_admin(user)
    now = datetime.now(timezone.utc)
    result = await db.execute(
        sa_update(ScanJob)
        .where(ScanJob.status.in_(["running", "pending"]))
        .values(
            status="failed",
            completed_at=now,
            error="reset by admin via /api/scans/reset (global)",
        )
    )
    affected = result.rowcount or 0
    await log_action(
        db, user, request, "scan.reset_all",
        target="*", details={"affected_jobs": affected},
    )
    await db.commit()
    return {"reset_count": affected}


@router.post("/reset/{app_id}")
async def reset_stuck_scans(
    app_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force every running/pending scan job for an app to ``failed``.

    Operator escape hatch when a job is wedged in ``running`` (worker
    died without raising, OOM-killed subprocess, etc.). Without this
    the concurrency check in ``_do_scan`` blocks every future scan
    for the app until the row is manually fixed in the DB.

    The scheduler also runs this sweep automatically on startup and at
    every tick (see scheduler._reset_stale_jobs), but admins may want
    to unblock a specific app immediately.
    """
    require_admin(user)
    app = await db.get(Application, app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    now = datetime.now(timezone.utc)
    result = await db.execute(
        sa_update(ScanJob)
        .where(
            ScanJob.application_id == app_id,
            ScanJob.status.in_(["running", "pending"]),
        )
        .values(
            status="failed",
            completed_at=now,
            error="reset by admin via /api/scans/reset",
        )
    )
    affected = result.rowcount or 0
    await log_action(
        db, user, request, "scan.reset",
        target=app.name, details={"affected_jobs": affected},
    )
    await db.commit()
    return {"app_id": str(app_id), "reset_count": affected}
