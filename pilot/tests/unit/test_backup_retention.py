"""GFS (grandfather-father-son) retention for centralized backups.

Pure-function tests for the helpers in ``src.routes.backups`` that decide
which backup snapshots survive: ``_gfs_keep`` keeps the most recent backup of
each of the last N days / weeks / months, and ``_normalize_cfg`` migrates the
legacy flat ``retention_count`` config to the GFS shape.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from src.routes.backups import (
    DEFAULT_RETENTION_MONTHLY,
    DEFAULT_RETENTION_WEEKLY,
    _gfs_keep,
    _key_timestamp,
    _normalize_cfg,
)


def _daily_keys(n: int, start=datetime(2026, 1, 1), mod="risk") -> list[str]:
    return [
        f"backup_{mod}_" + (start + timedelta(days=i)).strftime("%Y%m%d") + "_030000"
        for i in range(n)
    ]


def test_key_timestamp_parses_suffix():
    assert _key_timestamp("backup_risk_20260701_030000") == datetime(2026, 7, 1, 3, 0, 0)
    assert _key_timestamp("backup_risk_legacy") is None


def test_gfs_buckets_union_over_a_year():
    # 400 consecutive daily backups → every bucket is fully populated.
    keys = _daily_keys(400)
    keep = _gfs_keep(keys, daily=7, weekly=4, monthly=12)
    days = {_key_timestamp(k).strftime("%Y-%m-%d") for k in keep}
    weeks = {_key_timestamp(k).strftime("%G-%V") for k in keep}
    months = {_key_timestamp(k).strftime("%Y-%m") for k in keep}
    # Each bucket contributes its full quota of distinct periods.
    assert len(days) >= 7
    assert len(weeks) >= 4
    assert len(months) >= 12
    # The 7 newest days are always kept.
    newest7 = set(_daily_keys(400)[-7:])
    assert newest7 <= keep


def test_same_day_keeps_only_newest():
    keys = [
        "backup_risk_20260701_010000",
        "backup_risk_20260701_230000",
        "backup_risk_20260630_120000",
    ]
    keep = _gfs_keep(keys, daily=7, weekly=4, monthly=12)
    assert "backup_risk_20260701_230000" in keep
    assert "backup_risk_20260701_010000" not in keep  # older same-day dropped
    assert "backup_risk_20260630_120000" in keep


def test_undateable_keys_are_always_kept():
    keep = _gfs_keep(["backup_risk_legacy"], daily=7, weekly=4, monthly=12)
    assert "backup_risk_legacy" in keep


def test_zero_counts_delete_everything_datable():
    keys = _daily_keys(10)
    assert _gfs_keep(keys, daily=0, weekly=0, monthly=0) == set()


def test_fewer_backups_than_quota_keeps_all():
    keys = _daily_keys(3)
    assert _gfs_keep(keys, daily=7, weekly=4, monthly=12) == set(keys)


def test_normalize_migrates_legacy_retention_count():
    cfg = _normalize_cfg({"enabled": True, "frequency_hours": 24, "retention_count": 5})
    assert cfg["retention_daily"] == 5  # legacy count seeds the daily bucket
    assert cfg["retention_weekly"] == DEFAULT_RETENTION_WEEKLY
    assert cfg["retention_monthly"] == DEFAULT_RETENTION_MONTHLY


def test_normalize_defaults_for_empty_config():
    cfg = _normalize_cfg({})
    assert cfg == {
        "enabled": False,
        "frequency_hours": 24,
        "retention_daily": 7,
        "retention_weekly": 4,
        "retention_monthly": 12,
    }


def test_normalize_clamps_negatives_and_zero_frequency():
    cfg = _normalize_cfg({"frequency_hours": 0, "retention_daily": -3})
    assert cfg["frequency_hours"] == 1
    assert cfg["retention_daily"] == 0
