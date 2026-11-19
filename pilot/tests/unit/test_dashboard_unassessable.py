"""FEAT-73 — the dashboard counts the requirements an automated monitoring
could not assess, from the modules' posture (`posture.unassessable`)."""
import os
import sys

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes.dashboard import summarize_unassessable  # noqa: E402


def test_the_unassessable_requirements_are_summed_per_module():
    cards = [
        {"id": "compliance", "stats": {"posture": {"score": 29, "unassessable": 3}}},
        {"id": "risk", "stats": {"posture": {"score": 60}}},                  # no automated monitoring
        {"id": "audit", "stats": {"posture": {"unassessable": "x"}}},         # garbage is nothing
        {"id": "watch", "stats": {"posture": None}},
        {"id": "vendor", "stats": {}},
    ]
    assert summarize_unassessable(cards) == {"total": 3, "modules": {"compliance": 3}}


def test_no_module_says_none():
    assert summarize_unassessable([]) == {"total": 0, "modules": {}}
