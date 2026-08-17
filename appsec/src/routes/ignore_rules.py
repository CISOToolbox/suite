"""Ignore rules CRUD — admin-only."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.audit import log_action
from src.database import get_db
from src.ignore_engine import matches_rule
from src.models import Application, Finding, IgnoreRule, User

router = APIRouter(prefix="/api/ignore-rules", tags=["ignore-rules"])

_VALID_TYPES = {"cve_id", "package", "scanner_rule", "target_pattern", "severity", "ecosystem"}


class CriterionBody(BaseModel):
    type: str
    value: str


class IgnoreRuleCreate(BaseModel):
    application_ids: list[str] = []  # UUIDs as strings, empty = all
    criteria: list[CriterionBody]
    reason: str
    enabled: bool = True


class IgnoreRuleUpdate(BaseModel):
    application_ids: list[str] | None = None
    criteria: list[CriterionBody] | None = None
    reason: str | None = None
    enabled: bool | None = None


def _to_dict(r: IgnoreRule, app_names: dict | None = None) -> dict:
    app_names = app_names or {}
    aids = r.application_ids or []
    return {
        "id": str(r.id),
        "application_ids": aids,
        "application_names": [app_names.get(a, a) for a in aids],
        "criteria": r.criteria or [],
        "reason": r.reason,
        "enabled": r.enabled,
        "created_by": r.created_by or "",
        "created_at": r.created_at.isoformat() if r.created_at else "",
    }


async def _apply_rule_to_existing(db: AsyncSession, rule: IgnoreRule) -> int:
    """Apply a rule retroactively to existing findings that are still
    'new' or 'to_fix'. Returns the number of findings auto-triaged."""
    if not rule.enabled or not rule.criteria:
        return 0
    # Scope query to the rule's apps (or all if empty).
    query = select(Finding).where(Finding.status.in_(["new", "to_fix"]))
    app_ids = rule.application_ids or []
    if app_ids:
        from sqlalchemy import cast
        from sqlalchemy.dialects.postgresql import UUID as PG_UUID
        query = query.where(Finding.application_id.in_(
            [cast(a, PG_UUID) for a in app_ids]
        ))
    result = await db.execute(query)
    findings = result.scalars().all()
    count = 0
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    criteria_desc = " AND ".join(
        f"{c.get('type')}={c.get('value')}" for c in (rule.criteria or []) if isinstance(c, dict)
    )
    for f in findings:
        raw = {
            "cve_id": f.cve_id or "",
            "severity": f.severity or "",
            "scanner": f.scanner or "",
            "target": f.target or "",
            "evidence": f.evidence or {},
        }
        if matches_rule(raw, rule):
            f.status = "false_positive"
            f.triage_notes = f"[auto-ignore] {criteria_desc}: {rule.reason}"
            f.triaged_at = now
            f.triaged_by = "ignore-rule"
            f.updated_at = now
            count += 1
    if count:
        await db.flush()
    return count


def _criteria_summary(criteria: list) -> str:
    return " AND ".join(
        f"{c.get('type','?')}={c.get('value','?')}"
        for c in criteria if isinstance(c, dict)
    )[:200]


@router.get("")
async def list_rules(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    result = await db.execute(select(IgnoreRule).order_by(IgnoreRule.created_at.desc()))
    rules = result.scalars().all()
    # Resolve app names for display.
    all_ids = set()
    for r in rules:
        for a in (r.application_ids or []):
            all_ids.add(a)
    app_names = {}
    if all_ids:
        apps_q = await db.execute(select(Application.id, Application.name))
        app_names = {str(row[0]): row[1] for row in apps_q}
    return [_to_dict(r, app_names) for r in rules]


@router.post("", status_code=201)
async def create_rule(
    body: IgnoreRuleCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if not body.criteria:
        raise HTTPException(status_code=400, detail="At least one criterion is required")
    for c in body.criteria:
        if c.type not in _VALID_TYPES:
            raise HTTPException(status_code=400, detail=f"Invalid criteria type: {c.type}")
        if not c.value.strip():
            raise HTTPException(status_code=400, detail=f"Empty value for criteria type: {c.type}")
    if not body.reason.strip():
        raise HTTPException(status_code=400, detail="Reason is required")

    rule = IgnoreRule(
        application_ids=[str(a) for a in body.application_ids],
        criteria=[{"type": c.type, "value": c.value.strip()} for c in body.criteria],
        reason=body.reason.strip()[:2000],
        enabled=body.enabled,
        created_by=user.email if user else "",
    )
    db.add(rule)
    await log_action(db, user, request, "ignore_rule.create",
                     target=_criteria_summary(rule.criteria),
                     details={"reason": body.reason[:200], "apps": len(body.application_ids)})
    await db.commit()
    await db.refresh(rule)
    # Retroactively apply the new rule to existing findings.
    applied = await _apply_rule_to_existing(db, rule)
    if applied:
        await db.commit()
    return {**_to_dict(rule), "retroactive_count": applied}


@router.patch("/{rule_id}")
async def update_rule(
    rule_id: uuid.UUID,
    body: IgnoreRuleUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    rule = await db.get(IgnoreRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if body.application_ids is not None:
        rule.application_ids = [str(a) for a in body.application_ids]
    if body.criteria is not None:
        for c in body.criteria:
            if c.type not in _VALID_TYPES:
                raise HTTPException(status_code=400, detail=f"Invalid criteria type: {c.type}")
        rule.criteria = [{"type": c.type, "value": c.value.strip()} for c in body.criteria]
    if body.reason is not None:
        rule.reason = body.reason.strip()[:2000]
    if body.enabled is not None:
        rule.enabled = body.enabled
    await log_action(db, user, request, "ignore_rule.update",
                     target=_criteria_summary(rule.criteria))
    await db.commit()
    await db.refresh(rule)
    # Retroactively apply the updated rule to existing findings.
    applied = await _apply_rule_to_existing(db, rule)
    if applied:
        await db.commit()
    return {**_to_dict(rule), "retroactive_count": applied}


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    rule = await db.get(IgnoreRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await log_action(db, user, request, "ignore_rule.delete",
                     target=_criteria_summary(rule.criteria))
    await db.delete(rule)
    await db.commit()
