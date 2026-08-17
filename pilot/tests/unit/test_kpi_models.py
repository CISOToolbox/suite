"""Invariants of the KPI ORM models.

These tests run against the SQLite in-memory engine wired up in
``tests/conftest.py`` (a single ``db`` fixture per test, tables created
then dropped). They cover the foreign-key cascade and the uniqueness
constraints — anything a route bug could silently break."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.models import KpiDefinition, KpiFrameworkMapping, KpiSnapshot


def _make_kpi(**overrides) -> KpiDefinition:
    """Minimum valid KPI definition for tests."""
    defaults = dict(
        code="test_kpi",
        name_fr="Test KPI",
        name_en="Test KPI",
        category_primary="protect",
        unit="%",
        direction="higher_better",
        source_type="auto",
        source_module="risk",
    )
    defaults.update(overrides)
    return KpiDefinition(**defaults)


async def test_kpi_definition_code_is_unique(db):
    db.add(_make_kpi(code="dup"))
    await db.commit()

    db.add(_make_kpi(code="dup", name_fr="Another"))
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_kpi_definition_minimal_required_fields(db):
    """Confirms the fields we treat as mandatory at the schema level
    actually are. Catches accidental relaxation of ``nullable=False``."""
    bad = KpiDefinition(code="missing")  # no name_fr, no category, etc.
    db.add(bad)
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_kpi_snapshot_cascade_on_definition_delete(db):
    """Deleting a KPI must cascade-purge its snapshots: we never
    want orphan time-series rows pointing at a missing KPI."""
    k = _make_kpi(code="casc")
    db.add(k)
    await db.commit()
    await db.refresh(k)

    db.add(
        KpiSnapshot(
            kpi_id=k.id,
            value=Decimal("50"),
            captured_at=datetime.now(timezone.utc),
            source="auto",
        )
    )
    await db.commit()

    await db.delete(k)
    await db.commit()

    snaps = (
        await db.execute(
            select(KpiSnapshot).where(KpiSnapshot.kpi_id == k.id)
        )
    ).scalars().all()
    assert snaps == []


async def test_kpi_snapshot_idempotency_on_same_triplet(db):
    """``(kpi_id, captured_at, source)`` is the idempotency key for
    the ingest endpoint — re-posting the same datapoint must fail
    the unique constraint, not silently insert a duplicate."""
    k = _make_kpi(code="idem")
    db.add(k)
    await db.commit()
    await db.refresh(k)

    ts = datetime.now(timezone.utc)
    db.add(
        KpiSnapshot(kpi_id=k.id, value=Decimal("10"), captured_at=ts, source="auto")
    )
    await db.commit()

    db.add(
        KpiSnapshot(kpi_id=k.id, value=Decimal("99"), captured_at=ts, source="auto")
    )
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_kpi_snapshot_same_timestamp_different_source_allowed(db):
    """A KPI may legitimately receive two values at the same timestamp
    from two different sources (e.g. auto compute + manual override).
    The unique key includes ``source`` precisely to allow this."""
    k = _make_kpi(code="multi_source")
    db.add(k)
    await db.commit()
    await db.refresh(k)

    ts = datetime.now(timezone.utc)
    db.add_all(
        [
            KpiSnapshot(
                kpi_id=k.id, value=Decimal("10"), captured_at=ts, source="auto"
            ),
            KpiSnapshot(
                kpi_id=k.id,
                value=Decimal("12"),
                captured_at=ts,
                source="manual:admin@local",
            ),
        ]
    )
    await db.commit()

    snaps = (
        await db.execute(
            select(KpiSnapshot).where(KpiSnapshot.kpi_id == k.id)
        )
    ).scalars().all()
    assert len(snaps) == 2


async def test_kpi_framework_mapping_unique_per_triplet(db):
    """Same KPI + same framework + same ref code = duplicate mapping.
    Different ref codes within the same framework are fine."""
    k = _make_kpi(code="fw")
    db.add(k)
    await db.commit()
    await db.refresh(k)

    db.add(
        KpiFrameworkMapping(
            kpi_id=k.id, framework_code="NIST_CSF_2", ref_code="PR.PS-02"
        )
    )
    await db.commit()

    db.add(
        KpiFrameworkMapping(
            kpi_id=k.id, framework_code="NIST_CSF_2", ref_code="PR.PS-02"
        )
    )
    with pytest.raises(IntegrityError):
        await db.commit()


async def test_kpi_framework_mapping_multi_framework(db):
    """One KPI can map to N controls across N frameworks — this is the
    whole point of the table (CISO needs the same KPI under NIST CSF
    AND ISO 27001 AND CIS without duplicating its definition)."""
    k = _make_kpi(code="multi")
    db.add(k)
    await db.commit()
    await db.refresh(k)

    db.add_all(
        [
            KpiFrameworkMapping(
                kpi_id=k.id,
                framework_code="NIST_CSF_2",
                ref_code="PR.PS-02",
                ref_label_en="Configuration management",
            ),
            KpiFrameworkMapping(
                kpi_id=k.id,
                framework_code="ISO_27001_2022",
                ref_code="A.8.8",
                ref_label_en="Management of technical vulnerabilities",
            ),
            KpiFrameworkMapping(
                kpi_id=k.id,
                framework_code="CIS_v8",
                ref_code="7.1",
                ref_label_en="Establish and maintain a vulnerability management process",
            ),
        ]
    )
    await db.commit()

    rows = (
        await db.execute(
            select(KpiFrameworkMapping).where(KpiFrameworkMapping.kpi_id == k.id)
        )
    ).scalars().all()
    assert len(rows) == 3
    assert {r.framework_code for r in rows} == {
        "NIST_CSF_2",
        "ISO_27001_2022",
        "CIS_v8",
    }


async def test_kpi_framework_mapping_cascade(db):
    """Mappings must die with their KPI — same reasoning as snapshots."""
    k = _make_kpi(code="cascfw")
    db.add(k)
    await db.commit()
    await db.refresh(k)

    db.add(
        KpiFrameworkMapping(
            kpi_id=k.id, framework_code="NIST_CSF_2", ref_code="PR.PS-02"
        )
    )
    await db.commit()

    await db.delete(k)
    await db.commit()

    rows = (
        await db.execute(
            select(KpiFrameworkMapping).where(KpiFrameworkMapping.kpi_id == k.id)
        )
    ).scalars().all()
    assert rows == []
