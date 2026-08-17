"""KPI catalogue + time-series API.

Two access layers:

* ``POST /api/internal/kpi/ingest`` — service-token auth. Universal
  ingestion contract used by:
    - auto-compute scheduler (M153) — ``source="auto"``
    - plugins (phase-2 native integrations) — ``source="plugin:<name>"``
    - the manual UI wrapper below — ``source="manual:<email>"``
  Idempotent on ``(kpi_id, captured_at, source)``: replaying the same
  datapoint is a no-op (HTTP 200 with ``idempotent: true``), which lets
  plugins retry safely without dedup lookups.

* User-facing CRUD under ``/api/kpis`` (JWT auth):
    - ``GET    /api/kpis``                       — list with mappings + latest value
    - ``GET    /api/kpis/{code}``                — one KPI, with mappings + latest
    - ``GET    /api/kpis/{code}/snapshots``      — time-series, filterable
    - ``POST   /api/kpis/{code}/manual``         — wrap ingest as the logged-in user
    - ``POST   /api/kpis``                       — admin: create custom KPI + mappings
    - ``PATCH  /api/kpis/{code}``                — admin: tune target / thresholds / active
    - ``DELETE /api/kpis/{code}``                — admin: drop the KPI (cascades)
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin, verify_service_token
from src.database import get_db
from src.models import (
    KpiDefinition,
    KpiFrameworkMapping,
    KpiSnapshot,
    KpiTombstone,
    User,
)

router = APIRouter(tags=["kpis"])

# --------------------------------------------------------------------------- #
# Pydantic shapes                                                              #
# --------------------------------------------------------------------------- #

_VALID_CATEGORIES = {"govern", "identify", "protect", "detect", "respond", "recover"}
_VALID_UNITS = {"%", "count", "days", "score", "currency", "ratio"}
_VALID_DIRECTIONS = {"higher_better", "lower_better"}
_VALID_SOURCE_TYPES = {"auto", "external"}  # phase-2: 'computed', 'integration'


class MappingPayload(BaseModel):
    framework: str
    ref: str
    label_fr: str | None = None
    label_en: str | None = None


class KpiCreate(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    name_fr: str = Field(min_length=1, max_length=200)
    name_en: str = Field(min_length=1, max_length=200)
    description_fr: str | None = None
    description_en: str | None = None
    category_primary: Literal["govern", "identify", "protect", "detect", "respond", "recover"]
    unit: Literal["%", "count", "days", "score", "currency", "ratio"]
    direction: Literal["higher_better", "lower_better"]
    source_type: Literal["auto", "external"]
    source_module: str | None = None
    source_metric: str | None = None
    target: float | None = None
    threshold_amber: float | None = None
    threshold_red: float | None = None
    mappings: list[MappingPayload] = []


class KpiPatch(BaseModel):
    """User-tunable knobs. Definition shape (names, source…) is locked
    because catalogue KPIs would be reset at next boot anyway — see
    seeds/kpi_catalog.py.

    ``mappings`` is optional: when provided, it REPLACES the full set
    of framework mappings for this KPI (delete-then-insert). Pass
    ``None`` (or omit) to leave mappings untouched; pass ``[]`` to
    drop all mappings."""

    target: float | None = None
    threshold_amber: float | None = None
    threshold_red: float | None = None
    active: bool | None = None
    mappings: list[MappingPayload] | None = None


class IngestPayload(BaseModel):
    code: str
    value: float
    captured_at: datetime | None = None  # default: server "now"
    source: str | None = None            # default: 'auto'
    note: str | None = None
    raw_payload: dict[str, Any] | None = None


class ManualEntry(BaseModel):
    value: float
    captured_at: datetime | None = None
    note: str | None = None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

async def _get_kpi_by_code(db: AsyncSession, code: str) -> KpiDefinition:
    kpi = (
        await db.execute(select(KpiDefinition).where(KpiDefinition.code == code))
    ).scalar_one_or_none()
    if kpi is None:
        raise HTTPException(status_code=404, detail=f"KPI '{code}' not found")
    return kpi


async def _serialize_kpi(
    db: AsyncSession, kpi: KpiDefinition, with_latest: bool = True
) -> dict[str, Any]:
    mappings = (
        await db.execute(
            select(KpiFrameworkMapping).where(KpiFrameworkMapping.kpi_id == kpi.id)
        )
    ).scalars().all()

    latest: dict[str, Any] | None = None
    if with_latest:
        snap = (
            await db.execute(
                select(KpiSnapshot)
                .where(KpiSnapshot.kpi_id == kpi.id)
                .order_by(KpiSnapshot.captured_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if snap:
            latest = {
                "value": float(snap.value),
                "captured_at": snap.captured_at.isoformat(),
                "source": snap.source,
            }

    return {
        "id": str(kpi.id),
        "code": kpi.code,
        "name_fr": kpi.name_fr,
        "name_en": kpi.name_en,
        "description_fr": kpi.description_fr,
        "description_en": kpi.description_en,
        "category_primary": kpi.category_primary,
        "unit": kpi.unit,
        "direction": kpi.direction,
        "source_type": kpi.source_type,
        "source_module": kpi.source_module,
        "source_metric": kpi.source_metric,
        "connector_config": kpi.connector_config,
        "target": float(kpi.target) if kpi.target is not None else None,
        "threshold_amber": float(kpi.threshold_amber) if kpi.threshold_amber is not None else None,
        "threshold_red": float(kpi.threshold_red) if kpi.threshold_red is not None else None,
        "active": bool(kpi.active),
        "last_synced_at": kpi.last_synced_at.isoformat() if kpi.last_synced_at else None,
        "mappings": [
            {
                "framework": m.framework_code,
                "ref": m.ref_code,
                "label_fr": m.ref_label_fr,
                "label_en": m.ref_label_en,
            }
            for m in mappings
        ],
        "latest": latest,
    }


async def _ingest(
    db: AsyncSession,
    *,
    code: str,
    value: float,
    captured_at: datetime | None,
    source: str,
    note: str | None,
    raw_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Core ingest path shared by service-token and manual-UI entry points.

    Conflict policy on (kpi_id, captured_at, source):
      * source='auto'   → last-pass-wins: the scheduler buckets to the UTC
                          day, so multiple passes refresh the same row with
                          the latest value (replaced=True in the response).
      * any other source → idempotent: a duplicate write is a no-op and
                          returns the existing row with idempotent=True
                          (manual UI saves clicked twice, plugin retries…).
    """
    kpi = await _get_kpi_by_code(db, code)
    if not kpi.active:
        raise HTTPException(status_code=409, detail=f"KPI '{code}' is inactive")

    # Reaching here means the value was produced successfully → stamp the last
    # successful sync (real wall-clock, unlike the daily-bucketed captured_at).
    kpi.last_synced_at = datetime.now(timezone.utc)

    ts = captured_at or datetime.now(timezone.utc)

    # Pre-check the conflict triplet so we don't trip the UNIQUE constraint.
    existing = (
        await db.execute(
            select(KpiSnapshot).where(
                KpiSnapshot.kpi_id == kpi.id,
                KpiSnapshot.captured_at == ts,
                KpiSnapshot.source == source,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if source == "auto":
            # Same UTC-day bucket, fresher value — overwrite in place so
            # the history stays at one row per day per KPI.
            existing.value = Decimal(str(value))
            existing.raw_payload = raw_payload
            if note is not None:
                existing.note = note
            await db.commit()
            await db.refresh(existing)
            return {
                "id": str(existing.id),
                "kpi_code": kpi.code,
                "value": float(existing.value),
                "captured_at": existing.captured_at.isoformat(),
                "source": existing.source,
                "replaced": True,
            }
        return {
            "id": str(existing.id),
            "kpi_code": kpi.code,
            "value": float(existing.value),
            "captured_at": existing.captured_at.isoformat(),
            "source": existing.source,
            "idempotent": True,
        }

    snap = KpiSnapshot(
        kpi_id=kpi.id,
        value=Decimal(str(value)),
        captured_at=ts,
        source=source,
        note=note,
        raw_payload=raw_payload,
    )
    db.add(snap)
    # Insert the snapshot inside a SAVEPOINT so a UNIQUE-constraint conflict
    # rolls back ONLY this row, never the caller's pending work. _ingest is
    # called mid-transaction by the Proofpoint connector's _sync_kpis, which
    # stages a KPI rename + active flag + last_synced_at + framework mappings
    # *before* calling us. A bare db.rollback() here used to discard all of
    # that: a same-day re-sync tripped the (kpi_id, captured_at, source)
    # UNIQUE, rolled back the whole transaction, and returned "idempotent"
    # success — so the run reported "green, N KPI, 0 errors" while the card
    # title stayed "Complétion" and last_synced_at stayed NULL. The nested
    # transaction confines the rollback to the snapshot alone.
    try:
        async with db.begin_nested():
            await db.flush()
    except IntegrityError:
        # Same-day duplicate / race: the triplet already exists. The savepoint
        # already undid our snapshot; commit the caller's staged changes
        # (rename, last_synced_at, mappings) and report idempotent success.
        await db.commit()
        return {
            "kpi_code": kpi.code,
            "captured_at": ts.isoformat(),
            "source": source,
            "idempotent": True,
        }
    await db.commit()
    await db.refresh(snap)
    return {
        "id": str(snap.id),
        "kpi_code": kpi.code,
        "value": float(snap.value),
        "captured_at": snap.captured_at.isoformat(),
        "source": snap.source,
        "idempotent": False,
    }


# --------------------------------------------------------------------------- #
# Routes — internal (service token)                                            #
# --------------------------------------------------------------------------- #


@router.post("/api/internal/kpi/ingest")
async def internal_ingest(
    body: IngestPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Universal plugin / scheduler ingest endpoint."""
    verify_service_token(request)
    src = body.source or "auto"
    result = await _ingest(
        db,
        code=body.code,
        value=body.value,
        captured_at=body.captured_at,
        source=src,
        note=body.note,
        raw_payload=body.raw_payload,
    )
    # Journal only real writes — idempotent replays stay silent (FEAT-30 P3).
    if not (isinstance(result, dict) and result.get("idempotent")):
        from src.audit import log_write
        await log_write(db, None, request, "kpi.ingest", actor=src,
                        entity_type="kpi", entity_id=str(body.code), commit=True)
    return result


# --------------------------------------------------------------------------- #
# Routes — user-facing                                                         #
# --------------------------------------------------------------------------- #


@router.get("/api/kpis")
async def list_kpis(
    category: str | None = Query(None),
    source_type: str | None = Query(None),
    active: bool | None = Query(None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(KpiDefinition)
    if category:
        query = query.where(KpiDefinition.category_primary == category)
    if source_type:
        query = query.where(KpiDefinition.source_type == source_type)
    if active is not None:
        query = query.where(KpiDefinition.active == active)
    query = query.order_by(KpiDefinition.category_primary, KpiDefinition.code)
    kpis = (await db.execute(query)).scalars().all()
    return [await _serialize_kpi(db, k) for k in kpis]


@router.get("/api/kpis/{code}")
async def get_kpi(
    code: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    kpi = await _get_kpi_by_code(db, code)
    return await _serialize_kpi(db, kpi)


@router.get("/api/kpis/{code}/snapshots")
async def list_snapshots(
    code: str,
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    source: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    kpi = await _get_kpi_by_code(db, code)
    query = select(KpiSnapshot).where(KpiSnapshot.kpi_id == kpi.id)
    if since:
        query = query.where(KpiSnapshot.captured_at >= since)
    if until:
        query = query.where(KpiSnapshot.captured_at <= until)
    if source:
        query = query.where(KpiSnapshot.source == source)
    query = query.order_by(KpiSnapshot.captured_at.desc()).limit(limit)
    snaps = (await db.execute(query)).scalars().all()
    return [
        {
            "id": str(s.id),
            "value": float(s.value),
            "captured_at": s.captured_at.isoformat(),
            "source": s.source,
            "note": s.note,
        }
        for s in snaps
    ]


@router.post("/api/kpis/{code}/manual", status_code=201)
async def manual_entry(
    code: str,
    body: ManualEntry,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """User-auth wrapper around the universal ingest. Computes
    ``source="manual:<email>"`` so the audit trail records the human.
    Admin-only: manual KPI values are a privileged, audited write."""
    require_admin(user)
    email = user.email if user is not None else "anonymous"
    return await _ingest(
        db,
        code=code,
        value=body.value,
        captured_at=body.captured_at,
        source=f"manual:{email}",
        note=body.note,
        raw_payload=None,
    )


@router.patch("/api/kpis/{code}")
async def patch_kpi(
    code: str,
    body: KpiPatch,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Tune the user-modifiable knobs. The catalogue seed preserves
    these on re-seed (see seeds/kpi_catalog.py)."""
    require_admin(user)
    kpi = await _get_kpi_by_code(db, code)
    if body.target is not None:
        kpi.target = Decimal(str(body.target))
    if body.threshold_amber is not None:
        kpi.threshold_amber = Decimal(str(body.threshold_amber))
    if body.threshold_red is not None:
        kpi.threshold_red = Decimal(str(body.threshold_red))
    if body.active is not None:
        kpi.active = body.active
    # Framework mappings: when provided, REPLACE the full set so admins
    # can associate/dissociate referentials directly from the UI.
    # Note: catalogue KPI mappings are re-asserted by the boot seed
    # (kpi_catalog.py refreshes the mapping rows on every restart) —
    # so additions to seeded KPIs are reset at next reboot. Custom
    # KPIs (created via POST) keep user-managed mappings forever.
    if body.mappings is not None:
        await db.execute(
            sa_delete(KpiFrameworkMapping).where(
                KpiFrameworkMapping.kpi_id == kpi.id
            )
        )
        for m in body.mappings:
            db.add(
                KpiFrameworkMapping(
                    kpi_id=kpi.id,
                    framework_code=m.framework,
                    ref_code=m.ref,
                    ref_label_fr=m.label_fr,
                    ref_label_en=m.label_en,
                )
            )
    kpi.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return await _serialize_kpi(db, kpi)


@router.post("/api/kpis", status_code=201)
async def create_kpi(
    body: KpiCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a custom KPI (not in the seeded catalogue). Admin-only."""
    require_admin(user)
    existing = (
        await db.execute(
            select(KpiDefinition).where(KpiDefinition.code == body.code)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"KPI '{body.code}' already exists")

    kpi = KpiDefinition(
        code=body.code,
        name_fr=body.name_fr,
        name_en=body.name_en,
        description_fr=body.description_fr,
        description_en=body.description_en,
        category_primary=body.category_primary,
        unit=body.unit,
        direction=body.direction,
        source_type=body.source_type,
        source_module=body.source_module,
        source_metric=body.source_metric,
        target=Decimal(str(body.target)) if body.target is not None else None,
        threshold_amber=Decimal(str(body.threshold_amber)) if body.threshold_amber is not None else None,
        threshold_red=Decimal(str(body.threshold_red)) if body.threshold_red is not None else None,
        active=True,
    )
    db.add(kpi)
    await db.flush()

    for m in body.mappings:
        db.add(
            KpiFrameworkMapping(
                kpi_id=kpi.id,
                framework_code=m.framework,
                ref_code=m.ref,
                ref_label_fr=m.label_fr,
                ref_label_en=m.label_en,
            )
        )

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"Integrity error: {e.orig}")
    await db.refresh(kpi)
    return await _serialize_kpi(db, kpi, with_latest=False)


@router.post("/api/kpis/auto-compute")
async def trigger_auto_compute(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin-only on-demand auto-compute pass. The background scheduler
    runs hourly; this endpoint exists so admins can refresh KPIs
    immediately after a module produces new stats."""
    require_admin(user)
    from src.kpi_scheduler import compute_auto_kpis_once
    return await compute_auto_kpis_once(db)


@router.delete("/api/kpis/{code}", status_code=204)
async def delete_kpi(
    code: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Drop a KPI. ``kpi_framework_mapping`` and ``kpi_snapshot`` rows
    cascade-delete via FK ``ON DELETE CASCADE``."""
    require_admin(user)
    kpi = await _get_kpi_by_code(db, code)
    # Cascade destroys the kpi_snapshot time series — always journaled.
    from src.audit import log_write
    await log_write(db, user, None, "kpi.delete",
                    entity_type="kpi", entity_id=code, target=getattr(kpi, "name", "") or code)
    await db.delete(kpi)
    # Tombstone the code so the catalogue seed does not resurrect a deleted
    # built-in KPI on the next restart. Harmless for custom (non-catalogue)
    # KPIs — the seed simply never looks them up.
    if await db.get(KpiTombstone, code) is None:
        db.add(KpiTombstone(code=code))
    await db.commit()
