"""BUG-27 — a freshly created perimeter must not be instantly review-overdue.

The old logic counted any perimeter without a closed review as overdue the
moment it was created. review_overdue() now anchors the first due date on
created_at + frequency (matching the frontend _isReviewOverdue).
"""
import os
from datetime import datetime, timedelta, timezone

# src.routes.internal freezes SERVICE_TOKEN at import time; this module sorts
# before test_stats_review_n1.py, so it must set the same env defaults first
# or the whole-suite run breaks that test (import-order coupling).
os.environ.setdefault("SERVICE_TOKEN", "test-service-token")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")

from src.routes.internal import FREQ_DAYS, review_overdue  # noqa: E402


def _dt(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def test_fresh_perimeter_not_overdue():
    # Created today, no review yet — the exact BUG-27 scenario.
    assert review_overdue(None, _dt(0), "semestrielle") is False


def test_young_perimeter_not_overdue():
    assert review_overdue(None, _dt(30), "semestrielle") is False


def test_never_reviewed_becomes_overdue_after_frequency():
    assert review_overdue(None, _dt(FREQ_DAYS["semestrielle"] + 2), "semestrielle") is True


def test_never_reviewed_quarterly_overdue_after_92_days():
    assert review_overdue(None, _dt(93), "trimestrielle") is True
    assert review_overdue(None, _dt(90), "trimestrielle") is False


def test_unknown_created_at_treated_as_fresh():
    # Legacy rows exposed without a creation date: fresh, never overdue.
    assert review_overdue(None, None, "semestrielle") is False


def test_recent_closed_review_not_overdue():
    recent = _dt(10).date().isoformat()
    assert review_overdue(recent, _dt(400), "semestrielle") is False


def test_old_closed_review_overdue():
    old = _dt(FREQ_DAYS["semestrielle"] + 5).date().isoformat()
    assert review_overdue(old, _dt(400), "semestrielle") is True


def test_malformed_closed_at_counts_as_overdue():
    assert review_overdue("not-a-date", _dt(0), "semestrielle") is True


def test_unknown_frequency_defaults_to_semestrial():
    assert review_overdue(None, _dt(100), "exotique") is False
    assert review_overdue(None, _dt(184), "exotique") is True


def test_freq_table_matches_frontend():
    # The FE _freqDays table must stay aligned (BUG-27 flagged the divergence).
    assert FREQ_DAYS == {"mensuelle": 31, "trimestrielle": 92,
                         "semestrielle": 183, "annuelle": 365}
