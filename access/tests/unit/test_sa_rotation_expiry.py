"""FEAT-42 — rotation-overdue and expiry-bucket predicates (backend).

Locks: the "none" (no secret) exclusion from rotation-overdue, the new
540d/730d vocabulary, and the expired / expiring-soon split feeding the two
Pilot alerts. Plus the server-side validators for the two new fields.
"""
import os
from datetime import date, timedelta

import pytest
from fastapi import HTTPException

os.environ.setdefault("SERVICE_TOKEN", "test-service-token")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

from src.routes.applications import _norm_owner_email  # noqa: E402
from src.routes.internal import (ROT_DAYS, sa_expiry_bucket,  # noqa: E402
                                 sa_rotation_overdue)
from src.routes.service_accounts import _norm_date_expiration  # noqa: E402

TODAY = date(2026, 9, 5)


def _iso(days_ago: int) -> str:
    return (TODAY - timedelta(days=days_ago)).isoformat()


# ── rotation overdue ────────────────────────────────────────────


def test_no_secret_never_rotation_overdue():
    # FEAT-42: "Aucun secret" — nothing to rotate, whatever the policy says.
    assert sa_rotation_overdue("none", "30d", "", TODAY) is False
    assert sa_rotation_overdue("none", "30d", _iso(400), TODAY) is False


def test_dated_policy_no_rotation_recorded_is_overdue():
    assert sa_rotation_overdue("vault", "30d", "", TODAY) is True


def test_rotation_within_window_not_overdue():
    assert sa_rotation_overdue("vault", "90d", _iso(30), TODAY) is False


def test_rotation_past_window_overdue():
    assert sa_rotation_overdue("vault", "90d", _iso(91), TODAY) is True


def test_18_months_policy():
    assert ROT_DAYS["540d"] == 540
    assert sa_rotation_overdue("vault", "540d", _iso(500), TODAY) is False
    assert sa_rotation_overdue("vault", "540d", _iso(541), TODAY) is True


def test_24_months_policy():
    assert ROT_DAYS["730d"] == 730
    assert sa_rotation_overdue("vault", "730d", _iso(700), TODAY) is False
    assert sa_rotation_overdue("vault", "730d", _iso(731), TODAY) is True


def test_never_and_unknown_policies_not_overdue():
    assert sa_rotation_overdue("vault", "never", "", TODAY) is False
    assert sa_rotation_overdue("vault", "unknown", "", TODAY) is False


# ── expiry buckets (Pilot alerts) ───────────────────────────────


def test_expiry_bucket_none_when_unset_or_invalid():
    assert sa_expiry_bucket("", TODAY) is None
    assert sa_expiry_bucket("garbage", TODAY) is None


def test_expiry_bucket_far_future_none():
    assert sa_expiry_bucket((TODAY + timedelta(days=31)).isoformat(), TODAY) is None


def test_expiry_bucket_expiring_soon_includes_today():
    assert sa_expiry_bucket(TODAY.isoformat(), TODAY) == "expiring_soon"
    assert sa_expiry_bucket((TODAY + timedelta(days=30)).isoformat(), TODAY) == "expiring_soon"


def test_expiry_bucket_expired():
    assert sa_expiry_bucket((TODAY - timedelta(days=1)).isoformat(), TODAY) == "expired"


# ── server-side validation (m5) ─────────────────────────────────


def test_date_expiration_validator_accepts_iso_and_empty():
    assert _norm_date_expiration("2026-12-31") == "2026-12-31"
    assert _norm_date_expiration("") == ""
    assert _norm_date_expiration(None) == ""


def test_date_expiration_validator_rejects_garbage():
    with pytest.raises(HTTPException) as e:
        _norm_date_expiration("31/12/2026")
    assert e.value.status_code == 422


def test_owner_email_validator():
    assert _norm_owner_email("owner@corp.io") == "owner@corp.io"
    assert _norm_owner_email("  owner@corp.io  ") == "owner@corp.io"
    assert _norm_owner_email("") == ""
    with pytest.raises(HTTPException) as e:
        _norm_owner_email("not-an-email")
    assert e.value.status_code == 422
