"""Unit tests for the digest send-window check.

`_is_due` decides whether a user's preferred digest time falls inside
the current tick window. Bugs here either spam users (sending twice)
or silently skip days, so we cover the boundaries.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

# Force a 60s tick so digest.LENIENCY_MINUTES resolves to the floor (5 min) —
# all boundary tests in this file assume the 5-minute window. Must be set
# BEFORE digest.py is imported.
os.environ["WATCH_TICK_SECONDS"] = "60"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


class _U:
    def __init__(self, hour=7, minute=0, tz="Europe/Paris", enabled=True):
        self.digest_hour = hour
        self.digest_minute = minute
        self.digest_timezone = tz
        self.digest_enabled = enabled


def _utc(year, month, day, hour, minute=0):
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)


class TestIsDue:
    def test_exact_minute_paris(self):
        # 7am Paris = 5/6am UTC depending on DST. May → 5am UTC.
        from digest import _is_due
        u = _U(hour=7, minute=0, tz="Europe/Paris")
        # 2026-05-13 is CEST (UTC+2), so 7am Paris = 5am UTC.
        assert _is_due(u, _utc(2026, 5, 13, 5, 0))

    def test_within_leniency_window(self):
        from digest import _is_due
        u = _U(hour=7, minute=0, tz="Europe/Paris")
        # 5:04 UTC = 7:04 Paris — within the 5-minute leniency window.
        assert _is_due(u, _utc(2026, 5, 13, 5, 4))

    def test_just_after_leniency_window(self):
        from digest import _is_due
        u = _U(hour=7, minute=0, tz="Europe/Paris")
        # 5:06 UTC = 7:06 Paris — past 5-minute window.
        assert not _is_due(u, _utc(2026, 5, 13, 5, 6))

    def test_before_target_time(self):
        from digest import _is_due
        u = _U(hour=7, minute=0, tz="Europe/Paris")
        # 4:59 UTC = 6:59 Paris — before target.
        assert not _is_due(u, _utc(2026, 5, 13, 4, 59))

    def test_disabled_user_never_due(self):
        from digest import _is_due
        u = _U(hour=7, minute=0, tz="Europe/Paris", enabled=False)
        assert not _is_due(u, _utc(2026, 5, 13, 5, 0))

    def test_unknown_tz_falls_back_to_utc(self):
        from digest import _is_due
        u = _U(hour=12, minute=0, tz="Not/A/Real/Zone")
        # 12 UTC matches in fallback case.
        assert _is_due(u, _utc(2026, 5, 13, 12, 0))

    def test_dst_winter_paris(self):
        from digest import _is_due
        u = _U(hour=7, minute=0, tz="Europe/Paris")
        # 2026-01-15 is CET (UTC+1) → 7am Paris = 6am UTC.
        assert _is_due(u, _utc(2026, 1, 15, 6, 0))
        assert not _is_due(u, _utc(2026, 1, 15, 5, 0))
