from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin, require_min_role

# Role hierarchy for AppSec — keep in sync with Pilot's
# _MODULE_ROLES["appsec"] (viewer < triager < admin). Using the wrong
# hierarchy makes triagers hit a blanket 403 because their role is
# not in the list.
_APPSEC_ROLES = ["viewer", "triager", "admin"]
from src.audit import log_action
from src.database import get_db
from src.models import Application, Finding, User
from src.schemas import ApplicationCreate, ApplicationUpdate
from src.crypto import encrypt_token

router = APIRouter(prefix="/api/applications", tags=["applications"])


def _app_response(app: Application, stats: dict | None = None) -> dict:
    d = {
        "id": app.id, "name": app.name, "description": app.description,
        "repo_url": app.repo_url, "repo_branch": app.repo_branch,
        "has_token": bool(app.repo_token_encrypted),
        "scan_paths": app.scan_paths or [],
        "docker_images": app.docker_images or [],
        "has_image_token": bool(getattr(app, "image_token_encrypted", "")),
        "scan_frequency_hours": app.scan_frequency_hours,
        "enabled_scanners": app.enabled_scanners or [],
        "enabled": app.enabled, "criticality": app.criticality or "medium",
        "owner_id": app.owner_id,
        "last_scan_at": app.last_scan_at,
        "created_at": app.created_at, "updated_at": app.updated_at,
        "findings_critical": 0, "findings_high": 0,
        "findings_medium": 0, "findings_low": 0,
        "notification_emails": app.notification_emails or [],
        "notification_lang": app.notification_lang or "en",
    }
    if stats:
        d.update(stats)
    return d


@router.get("")
async def list_applications(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).order_by(Application.name))
    apps = result.scalars().all()

    app_ids = [a.id for a in apps]
    severity_counts = {}
    if app_ids:
        q = await db.execute(
            select(
                Finding.application_id,
                Finding.severity,
                func.count(Finding.id),
            )
            .where(Finding.application_id.in_(app_ids), Finding.status.in_(["new", "to_fix"]))
            .group_by(Finding.application_id, Finding.severity)
        )
        for app_id, sev, cnt in q:
            severity_counts.setdefault(app_id, {})[f"findings_{sev}"] = cnt

    return [_app_response(a, severity_counts.get(a.id)) for a in apps]


@router.post("", status_code=201)
async def create_application(
    body: ApplicationCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_min_role(user, "triager", _APPSEC_ROLES)
    app = Application(
        name=body.name,
        description=body.description,
        repo_url=body.repo_url,
        repo_branch=body.repo_branch,
        repo_token_encrypted=encrypt_token(body.repo_token) if body.repo_token else "",
        image_token_encrypted=encrypt_token(body.image_token) if body.image_token else "",
        scan_paths=body.scan_paths if hasattr(body, "scan_paths") else [],
        docker_images=body.docker_images,
        scan_frequency_hours=body.scan_frequency_hours,
        enabled_scanners=body.enabled_scanners,
        criticality=body.criticality,
        notification_emails=body.notification_emails,
        notification_lang=body.notification_lang,
        owner_id=user.id if user else None,
    )
    db.add(app)
    await log_action(db, user, request, "app.create", target=body.name)
    await db.commit()
    await db.refresh(app)
    return _app_response(app)


@router.get("/{app_id}")
async def get_application(
    app_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    q = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.application_id == app_id, Finding.status.in_(["new", "to_fix"]))
        .group_by(Finding.severity)
    )
    stats = {f"findings_{sev}": cnt for sev, cnt in q}
    return _app_response(app, stats)


@router.patch("/{app_id}")
async def update_application(
    app_id: uuid.UUID,
    body: ApplicationUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_min_role(user, "triager", _APPSEC_ROLES)
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    updates = body.model_dump(exclude_none=True)
    if "repo_token" in updates:
        app.repo_token_encrypted = encrypt_token(updates.pop("repo_token"))
    if "image_token" in updates:
        app.image_token_encrypted = encrypt_token(updates.pop("image_token"))
    changed = list(updates.keys())
    for k, v in updates.items():
        setattr(app, k, v)
    await log_action(db, user, request, "app.update", target=app.name, details={"fields": changed})
    await db.commit()
    await db.refresh(app)
    return _app_response(app)


@router.delete("/{app_id}", status_code=204)
async def delete_application(
    app_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    await log_action(db, user, request, "app.delete", target=app.name)
    await db.delete(app)
    await db.commit()


@router.post("/{app_id}/scan", status_code=202)
async def trigger_scan(
    app_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_min_role(user, "triager", _APPSEC_ROLES)
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Idempotent: if the app already has pending/running jobs, do not
    # stack more. Every duplicate click of "Scan now" used to add a
    # fresh batch of pending rows; only the most recent batch was
    # actually consumed (one per scanner), leaving the older rows in
    # ``pending`` until the 20-minute stale sweep finally swept them
    # up. Meanwhile the scheduler tick saw "pending jobs exist" and
    # refused to schedule the app at all. → user-visible "stuck scan".
    from src.models import ScanJob
    active_q = await db.execute(
        select(ScanJob).where(
            ScanJob.application_id == app.id,
            ScanJob.status.in_(["pending", "running"]),
        ).limit(1)
    )
    if active_q.scalar_one_or_none():
        await log_action(
            db, user, request, "scan.trigger_ignored",
            target=app.name, details={"reason": "scan_already_in_progress"},
        )
        await db.commit()
        return {
            "status": "scan_already_in_progress",
            "application_id": str(app_id),
        }

    await log_action(db, user, request, "scan.trigger", target=app.name)

    # Create pending scan jobs immediately so they appear in the UI
    import uuid as _uuid
    from datetime import datetime, timezone
    triggered_by = user.email if user else "manual"
    for scanner_name in (app.enabled_scanners or []):
        db.add(ScanJob(
            id=_uuid.uuid4(), application_id=app.id, scanner=scanner_name,
            status="pending", triggered_by=triggered_by,
            started_at=datetime.now(timezone.utc),
        ))
    await db.commit()

    from src.scheduler import trigger_scan as _trigger
    await _trigger(app_id, triggered_by=triggered_by)
    return {"status": "scan_triggered", "application_id": str(app_id)}
