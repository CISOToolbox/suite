"""Perf regression: _compute_kpi_posture must still pick the LATEST snapshot
per KPI after the N+1 rewrite.

The per-KPI SELECT-LIMIT-1 loop (1 + N queries on every dashboard GET, polled
every 30s) was replaced by a single ordered query deduplicated in Python. This
test locks the behaviour the rewrite must preserve: only the newest snapshot of
each KPI feeds the posture, older ones are ignored.
"""
from datetime import datetime, timezone

import pytest

from src.models import KpiDefinition, KpiSnapshot
from src.routes.dashboard import _compute_kpi_posture

pytestmark = pytest.mark.asyncio


def _kpi(code):
    # higher_better with target=100/amber=50/red=20: value>=100 → green, value<20 → red
    return KpiDefinition(
        code=code, name_fr=code, name_en=code, category_primary="secu",
        unit="pct", direction="higher_better", source_type="external", active=True,
        target=100, threshold_amber=50, threshold_red=20,
    )


def _snap(kpi_id, value, day):
    return KpiSnapshot(
        kpi_id=kpi_id, value=value,
        captured_at=datetime(2026, day, 1, tzinfo=timezone.utc), source="test",
    )


async def test_posture_uses_latest_snapshot_per_kpi(db):
    a, b = _kpi("KA"), _kpi("KB")
    db.add_all([a, b])
    await db.flush()
    db.add_all([
        _snap(a.id, 10, 1),    # old → red
        _snap(a.id, 100, 6),   # latest → green
        _snap(b.id, 100, 3),   # green
    ])
    await db.commit()
    # Both green via the LATEST snapshot → 100.0. If A's stale red snapshot
    # leaked in it would be (100)/2 = 50.0.
    assert await _compute_kpi_posture(db) == 100.0


async def test_returns_none_when_no_snapshots(db):
    db.add(_kpi("KC"))
    await db.commit()
    assert await _compute_kpi_posture(db) is None
