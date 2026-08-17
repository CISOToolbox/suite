from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.auth import get_current_user, require_min_role
from src.audit import log_action
from src.database import get_db
from src.models import Application, Finding, Measure, User
from src.schemas import FindingResponse, FindingTriage, FindingsStats

router = APIRouter(prefix="/api/findings", tags=["findings"])

# Keep in sync with applications.py and Pilot's _MODULE_ROLES["appsec"].
_APPSEC_ROLES = ["viewer", "triager", "admin"]


@router.get("")
async def list_findings(
    app_id: uuid.UUID | None = Query(None),
    severity: str | None = Query(None),
    scanner: str | None = Query(None),
    status: str | None = Query(None),
    type: str | None = Query(None),
    q: str | None = Query(None),
    patch: str | None = Query(None),  # "available", "unavailable", None = all
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(Finding).order_by(
        func.array_position(["critical", "high", "medium", "low", "info"], Finding.severity),
        Finding.created_at.desc(),
    )
    if app_id:
        query = query.where(Finding.application_id == app_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if scanner:
        query = query.where(Finding.scanner == scanner)
    if status:
        query = query.where(Finding.status == status)
    if type:
        query = query.where(Finding.type == type)
    if patch == "available":
        # Only CVE findings where Trivy reported a fixed_version string.
        query = query.where(
            Finding.type == "cve",
            Finding.evidence["fixed_version"].astext != "",
            Finding.evidence["fixed_version"].astext.isnot(None),
        )
    elif patch == "unavailable":
        query = query.where(
            Finding.type == "cve",
            or_(
                Finding.evidence["fixed_version"].astext == "",
                Finding.evidence["fixed_version"].astext.is_(None),
            ),
        )
    if q:
        like = f"%{q}%"
        query = query.where(or_(
            Finding.title.ilike(like),
            Finding.target.ilike(like),
            Finding.cve_id.ilike(like),
        ))

    total_q = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_q.scalar() or 0

    result = await db.execute(query.offset(offset).limit(limit))
    findings = result.scalars().all()

    app_ids = list(set(f.application_id for f in findings))
    app_names = {}
    if app_ids:
        apps_q = await db.execute(select(Application.id, Application.name).where(Application.id.in_(app_ids)))
        app_names = {row[0]: row[1] for row in apps_q}

    items = []
    for f in findings:
        d = FindingResponse.model_validate(f).model_dump()
        d["application_name"] = app_names.get(f.application_id, "")
        items.append(d)

    return {"items": items, "total": total}


@router.get("/stats")
async def findings_stats(
    app_id: uuid.UUID | None = Query(None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    base = select(Finding)
    if app_id:
        base = base.where(Finding.application_id == app_id)

    active = base.where(Finding.status.in_(["new", "to_fix"]))

    total_q = await db.execute(select(func.count()).select_from(active.subquery()))
    total = total_q.scalar() or 0

    sev_base = select(Finding.severity, func.count(Finding.id)).where(Finding.status.in_(["new", "to_fix"]))
    if app_id:
        sev_base = sev_base.where(Finding.application_id == app_id)
    sev_q = await db.execute(sev_base.group_by(Finding.severity))
    by_sev = {sev: cnt for sev, cnt in sev_q}

    status_base = select(Finding.status, func.count(Finding.id))
    if app_id:
        status_base = status_base.where(Finding.application_id == app_id)
    status_q = await db.execute(status_base.group_by(Finding.status))
    by_status = {s: c for s, c in status_q}

    scanner_base = select(Finding.scanner, func.count(Finding.id)).where(Finding.status.in_(["new", "to_fix"]))
    if app_id:
        scanner_base = scanner_base.where(Finding.application_id == app_id)
    scanner_q = await db.execute(scanner_base.group_by(Finding.scanner))

    app_q_base = (
        select(Application.name, func.count(Finding.id))
        .join(Finding, Finding.application_id == Application.id)
        .where(Finding.status.in_(["new", "to_fix"]))
    )
    if app_id:
        app_q_base = app_q_base.where(Finding.application_id == app_id)
    app_q = await db.execute(app_q_base.group_by(Application.name))

    # Per-app severity breakdown — one SQL query grouped by (app, severity).
    app_sev_base = (
        select(Application.name, Finding.severity, func.count(Finding.id))
        .join(Finding, Finding.application_id == Application.id)
        .where(Finding.status.in_(["new", "to_fix"]))
    )
    if app_id:
        app_sev_base = app_sev_base.where(Finding.application_id == app_id)
    app_sev_q = await db.execute(
        app_sev_base.group_by(Application.name, Finding.severity)
    )
    by_app_severity: dict[str, dict[str, int]] = {}
    for app_name, sev, cnt in app_sev_q:
        by_app_severity.setdefault(app_name, {}).update({sev: cnt})

    # Patch availability stats on active CVE findings.
    patch_base = select(func.count(Finding.id)).where(
        Finding.status.in_(["new", "to_fix"]),
        Finding.type == "cve",
    )
    if app_id:
        patch_base = patch_base.where(Finding.application_id == app_id)
    cve_total = (await db.execute(patch_base)).scalar() or 0
    cve_with_patch = (await db.execute(
        patch_base.where(
            Finding.evidence["fixed_version"].astext != "",
            Finding.evidence["fixed_version"].astext.isnot(None),
        )
    )).scalar() or 0

    return FindingsStats(
        total=total,
        critical=by_sev.get("critical", 0),
        high=by_sev.get("high", 0),
        medium=by_sev.get("medium", 0),
        low=by_sev.get("low", 0),
        info=by_sev.get("info", 0),
        new=by_status.get("new", 0),
        to_fix=by_status.get("to_fix", 0),
        false_positive=by_status.get("false_positive", 0),
        fixed=by_status.get("fixed", 0),
        by_scanner={s: c for s, c in scanner_q},
        by_app={n: c for n, c in app_q},
        by_app_severity=by_app_severity,
        cve_total=cve_total,
        cve_with_patch=cve_with_patch,
    )


@router.get("/{finding_id}")
async def get_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    app_q = await db.execute(select(Application.name).where(Application.id == finding.application_id))
    app_name = app_q.scalar() or ""
    d = FindingResponse.model_validate(finding).model_dump()
    d["application_name"] = app_name
    return d


@router.patch("/{finding_id}")
async def triage_finding(
    finding_id: uuid.UUID,
    body: FindingTriage,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_min_role(user, "triager", _APPSEC_ROLES)
    result = await db.execute(
        select(Finding).options(selectinload(Finding.measure), selectinload(Finding.application)).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    app_name = finding.application.name if finding.application else "?"
    old_status = finding.status
    now = datetime.now(timezone.utc)
    finding.status = body.status
    if body.triage_notes is not None:
        finding.triage_notes = body.triage_notes
    finding.triaged_at = now
    finding.triaged_by = user.email if user else "anonymous"
    finding.updated_at = now
    await log_action(db, user, request, "finding.triage",
                     target=f"{app_name} / {finding.cve_id or finding.title[:60]}",
                     details={"from": old_status, "to": body.status})

    if body.status == "to_fix":
        # Existing link (legacy finding_id OR new finding_ids JSONB)?
        existing_q = await db.execute(
            select(Measure).where(Measure.finding_id == finding.id)
        )
        existing = existing_q.scalar_one_or_none()
        if existing is None:
            # Also check the JSONB array via a Python filter — cheap here
            # (measures count is bounded) and avoids the asyncpg jsonb ?|
            # operator cast pitfall.
            all_q = await db.execute(select(Measure))
            for m in all_q.scalars().all():
                if str(finding.id) in (m.finding_ids or []):
                    existing = m
                    break

        if existing is None:
            # Create a new measure — use the fields the frontend passed
            # (measure_title / description / responsable / echeance) so
            # single-finding triage produces the same shape as bulk.
            count_q = await db.execute(select(func.count()).select_from(select(Measure).subquery()))
            idx = (count_q.scalar() or 0) + 1
            title = (body.measure_title or finding.title or "")[:500].strip()
            description = (body.measure_description or finding.description or "")[:2000].strip()
            db.add(Measure(
                id=f"MES-{uuid.uuid4().hex[:8].upper()}",
                finding_id=finding.id,
                finding_ids=[str(finding.id)],
                sort_order=idx,
                title=title,
                description=description,
                statut="a_faire",
                responsable=(body.responsable or "").strip(),
                echeance=(body.echeance or "").strip(),
            ))
        else:
            # Update the existing linked measure with whatever the user
            # edited on the detail page (no-op when the fields are None).
            if body.measure_title is not None:
                existing.title = body.measure_title.strip()[:500]
            if body.measure_description is not None:
                existing.description = body.measure_description.strip()[:2000]
            if body.responsable is not None:
                existing.responsable = body.responsable.strip()
            if body.echeance is not None:
                existing.echeance = body.echeance.strip()
            existing.updated_at = now

    await db.commit()
    await db.refresh(finding)
    # Serialize manually to avoid model_validate triggering a relationship
    # access that isn't eager-loaded after the commit refresh.
    d = FindingResponse.model_validate(finding).model_dump()
    return d


from pydantic import BaseModel as _BM, Field as _F


class BulkTriageRequest(_BM):
    ids: list[uuid.UUID] = _F(..., min_length=1, max_length=500)
    status: str
    triage_notes: str | None = None
    # Only consumed when status == "to_fix": the bulk UI asks the user to
    # fill a measure form once, then we create a SINGLE Measure covering
    # every finding that doesn't already have one.
    measure_title: str | None = None
    measure_description: str | None = None
    responsable: str | None = None
    echeance: str | None = None


@router.post("/bulk-triage")
async def bulk_triage(
    body: BulkTriageRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Apply the same triage to N findings at once.

    For status == "to_fix":
      - Require a measure_title (the UI captures it before submit)
      - Update status/triaged_* on every finding in body.ids
      - Partition findings: those already linked to a Measure (via
        Measure.finding_id or Measure.finding_ids) vs the rest
      - Create ONE Measure covering the "rest" with finding_ids=[...]
      - Existing measures keep their link and get their fields
        (title/description/responsable/echeance) updated to mirror the
        bulk decision
    Other statuses just update triage metadata.
    """
    require_min_role(user, "triager", _APPSEC_ROLES)
    if body.status not in ("new", "false_positive", "to_fix", "fixed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    if body.status == "to_fix" and not (body.measure_title or "").strip():
        raise HTTPException(status_code=400, detail="Le nom de la mesure est obligatoire")

    result = await db.execute(
        select(Finding).options(selectinload(Finding.application)).where(Finding.id.in_(body.ids))
    )
    findings = result.scalars().all()
    if not findings:
        raise HTTPException(status_code=404, detail="Aucun finding trouvé pour les ids fournis")

    targets = [{"app": f.application.name if f.application else "?",
                "finding": f.cve_id or f.title[:60]} for f in findings]
    await log_action(db, user, request, "finding.bulk_triage",
                     target=f"{len(findings)} findings",
                     details={"status": body.status, "findings": targets})

    now = datetime.now(timezone.utc)
    triaged_by = user.email if user else "anonymous"

    # Update status/notes on every finding in the request
    for f in findings:
        f.status = body.status
        f.triaged_at = now
        f.triaged_by = triaged_by
        if body.triage_notes is not None:
            f.triage_notes = body.triage_notes
        f.updated_at = now

    measures_created = 0

    if body.status == "to_fix":
        # Simple semantics: each bulk triage creates ONE new Measure
        # covering exactly the selected findings — no merging with
        # existing measures. finding_ids always reflects the user's
        # current selection. If a finding was already in a previous
        # measure, that measure is left untouched (it still exists,
        # still groups its original findings); the user just gets an
        # additional measure. This keeps the "Findings" count accurate
        # from the operator's point of view: "I selected N findings,
        # I get a measure covering N findings."
        count_q = await db.execute(select(func.count()).select_from(select(Measure).subquery()))
        idx = (count_q.scalar() or 0) + 1
        primary = findings[0]
        # Dedupe the id list and preserve the user's selection order.
        seen: set[str] = set()
        unique_ids: list[str] = []
        for f in findings:
            s = str(f.id)
            if s not in seen:
                seen.add(s)
                unique_ids.append(s)
        description = (
            body.measure_description
            or (primary.description or "")
        ).strip()
        db.add(Measure(
            id=f"MES-{uuid.uuid4().hex[:8].upper()}",
            finding_id=primary.id,
            finding_ids=unique_ids,
            sort_order=idx,
            title=body.measure_title.strip()[:500],
            description=description[:2000],
            statut="a_faire",
            responsable=(body.responsable or "").strip(),
            echeance=(body.echeance or "").strip(),
        ))
        measures_created = 1

    await db.commit()
    return {
        "updated": len(findings),
        "status": body.status,
        "measures_created": measures_created,
    }
