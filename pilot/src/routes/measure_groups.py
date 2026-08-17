"""FEAT-11 — meta-measures: link N cached measures and steer them as one.

A MeasureGroup carries the canonical operational fields (status, due_date,
responsible). Editing them propagates to every member's source module through
the shared write-back (write_back_measure). Title/description stay per-module.
Groups are internal to Pilot: the /api/internal/measures contract of the
modules is untouched.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_writer
from src.database import get_db
from src.models import MeasureCache, MeasureGroup, MeasureGroupMember, ModuleRegistry, User
from src.routes.measures import write_back_measure

router = APIRouter(prefix="/api/measure-groups", tags=["measure-groups"])

_VALID_STATUSES = {"planned", "in_progress", "completed", "backlog"}
# Canonical group fields → module PATCH vocabulary.
_FIELD_MAP = {"status": "status", "due_date": "due_date", "responsible": "assignee"}


class GroupCreate(BaseModel):
    measure_ids: list[str]
    title: str = ""
    canonical_measure_id: str | None = None  # defaults to the first member


class GroupUpdate(BaseModel):
    title: str | None = None
    status: str | None = None
    due_date: str | None = None
    responsible: str | None = None


class MemberAdd(BaseModel):
    measure_ids: list[str]


def _member_dict(mc: MeasureCache) -> dict:
    d = mc.data or {}
    return {
        "id": str(mc.id), "module": mc.module, "source_id": mc.source_id,
        "entity_id": mc.entity_id or "", "entity_name": mc.entity_name or "",
        "title": d.get("title", ""), "status": d.get("status", ""),
        "assignee": d.get("assignee", ""), "due_date": d.get("due_date", ""),
    }


async def _next_ref(db: AsyncSession) -> str:
    """Next sequential META-NNN. Refs are never reused: the counter follows
    the highest existing number, not the row count."""
    refs = (await db.execute(select(MeasureGroup.ref))).scalars().all()
    top = 0
    for r in refs:
        if r and r.startswith("META-"):
            try:
                top = max(top, int(r[5:]))
            except ValueError:
                pass
    return f"META-{top + 1:03d}"


def _group_dict(g: MeasureGroup, members: list[MeasureCache]) -> dict:
    return {
        "id": str(g.id), "ref": g.ref or "", "title": g.title or "",
        "status": g.status or "planned", "due_date": g.due_date or "",
        "responsible": g.responsible or "",
        "members": [_member_dict(mc) for mc in members],
    }


async def _load_members(db: AsyncSession, group_id) -> list[MeasureCache]:
    rows = (await db.execute(
        select(MeasureCache)
        .join(MeasureGroupMember, MeasureGroupMember.measure_id == MeasureCache.id)
        .where(MeasureGroupMember.group_id == group_id)
        .order_by(MeasureCache.module, MeasureCache.source_id)
    )).scalars().all()
    return list(rows)


async def _propagate(db: AsyncSession, members: list[MeasureCache], fields: dict,
                     force: bool = False) -> list[dict]:
    """Push canonical fields to every member (source module first, cache after).
    Returns per-member errors ([] when all fine).

    The cache is only updated when the module write-back SUCCEEDS: updating
    it optimistically left cache == canonical after a transient failure, so
    every later propagation skipped the member as "already equal" and the
    divergence became unrepairable. ``force=True`` (the resync button)
    bypasses the already-equal skip entirely. Pilot-native members have no
    external module — cache only."""
    patch = {_FIELD_MAP[k]: v for k, v in fields.items() if k in _FIELD_MAP and v is not None}
    if not patch:
        return []
    mods = {m.id: m for m in (await db.execute(select(ModuleRegistry))).scalars().all()}
    errors = []
    for mc in members:
        data = dict(mc.data or {})
        # Journal noise rule: only touch/write when something actually
        # changes — unless a resync forces the re-push.
        if not force and all(data.get(k) == v for k, v in patch.items()):
            continue
        if mc.module != "pilot":
            mod = mods.get(mc.module)
            if not mod or not mod.internal_url:
                errors.append({"member": f"{mc.module}/{mc.source_id}", "error": "module not registered"})
                continue
            ok = await write_back_measure(mc, patch, mod, raise_on_error=False)
            if not ok:
                errors.append({"member": f"{mc.module}/{mc.source_id}", "error": "write-back failed"})
                continue
        data.update(patch)
        mc.data = data
        mc.synced_at = datetime.now(timezone.utc)
    return errors


async def _log(db, user, action: str, g: MeasureGroup, details=None):
    try:
        from src.audit import log_write
        await log_write(db, user, None, action, entity_type="measure_group",
                        entity_id=str(g.id), target=g.title or str(g.id), details=details or "")
    except ImportError:
        pass


@router.get("")
async def list_groups(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    groups = (await db.execute(select(MeasureGroup).order_by(MeasureGroup.created_at))).scalars().all()
    out = []
    for g in groups:
        out.append(_group_dict(g, await _load_members(db, g.id)))
    return out


@router.post("", status_code=201)
async def create_group(body: GroupCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    ids = []
    for raw in body.measure_ids:
        try:
            ids.append(uuid.UUID(raw))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid measure id: {raw}")
    if len(set(ids)) < 2:
        raise HTTPException(status_code=422, detail="A group needs at least 2 distinct measures")
    members = (await db.execute(select(MeasureCache).where(MeasureCache.id.in_(ids)))).scalars().all()
    if len(members) != len(set(ids)):
        raise HTTPException(status_code=404, detail="Some measures were not found in the cache")
    taken = (await db.execute(
        select(MeasureGroupMember.measure_id).where(MeasureGroupMember.measure_id.in_(ids))
    )).scalars().all()
    if taken:
        raise HTTPException(status_code=409, detail="A measure already belongs to another group")

    by_id = {str(mc.id): mc for mc in members}
    canonical = by_id.get(body.canonical_measure_id or "") or members[0]
    cd = canonical.data or {}
    g = MeasureGroup(
        ref=await _next_ref(db),
        title=body.title.strip() or cd.get("title", ""),
        status=cd.get("status") if cd.get("status") in _VALID_STATUSES else "planned",
        due_date=cd.get("due_date", "") or "",
        responsible=cd.get("assignee", "") or "",
    )
    db.add(g)
    await db.flush()
    for mc in members:
        db.add(MeasureGroupMember(group_id=g.id, measure_id=mc.id))
    errors = await _propagate(db, members, {
        "status": g.status, "due_date": g.due_date, "responsible": g.responsible})
    await _log(db, user, "measure_group.create", g,
               {"members": [f"{m.module}/{m.source_id}" for m in members]})
    await db.commit()
    return {**_group_dict(g, members), "propagation_errors": errors}


@router.patch("/{group_id}")
async def update_group(group_id: uuid.UUID, body: GroupUpdate,
                       user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    g = await db.get(MeasureGroup, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    if body.status is not None and body.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    changed = {}
    if body.title is not None and body.title != g.title:
        g.title = body.title
    for f in ("status", "due_date", "responsible"):
        v = getattr(body, f)
        if v is not None and v != getattr(g, f):
            setattr(g, f, v)
            changed[f] = v
    members = await _load_members(db, g.id)
    errors = await _propagate(db, members, changed) if changed else []
    if changed:
        await _log(db, user, "measure_group.update", g, changed)
    await db.commit()
    return {**_group_dict(g, members), "propagation_errors": errors}


@router.post("/{group_id}/resync")
async def resync_group(group_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Re-push the canonical fields to every member (divergence repair)."""
    require_writer(user)
    g = await db.get(MeasureGroup, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    members = await _load_members(db, g.id)
    errors = await _propagate(db, members, {
        "status": g.status, "due_date": g.due_date, "responsible": g.responsible}, force=True)
    await _log(db, user, "measure_group.resync", g)
    await db.commit()
    return {**_group_dict(g, members), "propagation_errors": errors}


@router.post("/{group_id}/members")
async def add_members(group_id: uuid.UUID, body: MemberAdd,
                      user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_writer(user)
    g = await db.get(MeasureGroup, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    ids = [uuid.UUID(r) for r in body.measure_ids]
    members = (await db.execute(select(MeasureCache).where(MeasureCache.id.in_(ids)))).scalars().all()
    if len(members) != len(set(ids)):
        raise HTTPException(status_code=404, detail="Some measures were not found in the cache")
    taken = (await db.execute(
        select(MeasureGroupMember.measure_id).where(MeasureGroupMember.measure_id.in_(ids))
    )).scalars().all()
    if taken:
        raise HTTPException(status_code=409, detail="A measure already belongs to a group")
    for mc in members:
        db.add(MeasureGroupMember(group_id=g.id, measure_id=mc.id))
    errors = await _propagate(db, members, {
        "status": g.status, "due_date": g.due_date, "responsible": g.responsible})
    await _log(db, user, "measure_group.attach", g,
               {"members": [f"{m.module}/{m.source_id}" for m in members]})
    await db.commit()
    return {**_group_dict(g, await _load_members(db, g.id)), "propagation_errors": errors}


@router.delete("/{group_id}/members/{measure_id}")
async def detach_member(group_id: uuid.UUID, measure_id: uuid.UUID,
                        user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Detach = the measure becomes standalone again, values untouched."""
    require_writer(user)
    g = await db.get(MeasureGroup, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    link = (await db.execute(select(MeasureGroupMember).where(
        MeasureGroupMember.group_id == group_id,
        MeasureGroupMember.measure_id == measure_id))).scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=404, detail="Not a member of this group")
    await db.delete(link)
    remaining = await _load_members(db, g.id)
    remaining = [m for m in remaining if m.id != measure_id]
    # A group of one is no longer a link — dissolve it silently.
    dissolved = False
    if len(remaining) < 2:
        for m2 in (await db.execute(select(MeasureGroupMember).where(
                MeasureGroupMember.group_id == group_id))).scalars().all():
            await db.delete(m2)
        await db.delete(g)
        dissolved = True
    await _log(db, user, "measure_group.detach", g, {"measure": str(measure_id), "dissolved": dissolved})
    await db.commit()
    return {"ok": True, "dissolved": dissolved}


@router.delete("/{group_id}", status_code=204)
async def dissolve_group(group_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Dissolve: every member becomes standalone again, values untouched."""
    require_writer(user)
    g = await db.get(MeasureGroup, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    await _log(db, user, "measure_group.dissolve", g)
    for link in (await db.execute(select(MeasureGroupMember).where(
            MeasureGroupMember.group_id == group_id))).scalars().all():
        await db.delete(link)
    await db.delete(g)
    await db.commit()
