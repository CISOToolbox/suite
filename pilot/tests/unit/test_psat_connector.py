"""Unit tests for the Proofpoint PSAT connector pure logic (FEAT-18).

No DB / no HTTP — exercises the parsing + filtering invariants:
* ``_attr`` resolves attributes case-insensitively across candidate names.
* ``_parse_training`` keeps only tracked campaigns and detects completion.
* ``_build_access_payload`` pushes the Access proof ONLY for users on a
  configured email domain who completed EVERY mandatory campaign.
* ``_build_reporting`` computes per-campaign completion (tenant-wide, no
  domain filter), the overall mandatory rate and the overdue list.
"""
from __future__ import annotations

from src.connectors.proofpoint_psat import (
    _attr,
    _build_access_payload,
    _build_reporting,
    _is_completed,
    _parse_training,
    _split,
    _to_int,
)

MANDATORY = "Sensibilisation annuelle 2026"
OPTIONAL = "Phishing - Module avancé"


def _cfg():
    return {
        "email_domains": ["acme.com"],
        "tracked_campaigns": [MANDATORY, OPTIONAL],
        "mandatory_campaigns": [MANDATORY],
    }


def test_split_and_to_int():
    assert _split("a.com, b.fr ,, c.io", ",") == ["a.com", "b.fr", "c.io"]
    assert _split("X; Y\nZ", ";") == ["X", "Y", "Z"]
    assert _to_int("365", 0) == 365
    assert _to_int("", 365) == 365
    assert _to_int("abc", 7) == 7


def test_attr_case_insensitive_candidates():
    attrs = {"UserEmailAddress": "a@acme.example", "AssignmentStatus": "Completed"}
    assert _attr(attrs, "useremailaddress") == "a@acme.example"
    assert _attr(attrs, "campaignname", "assignmentname") is None
    assert _is_completed(_attr(attrs, "assignmentstatus", "status")) is True
    assert _is_completed("In Progress") is False


def test_parse_training_filters_tracked_campaigns():
    records = [
        {"attributes": {"useremailaddress": "a@acme.example", "campaignname": MANDATORY,
                        "assignmentstatus": "Completed", "completiondate": "2026-05-01T10:00:00Z"}},
        {"attributes": {"useremailaddress": "a@acme.example", "campaignname": "Untracked campaign",
                        "assignmentstatus": "Completed"}},
        {"attributes": {"useremailaddress": "b@acme.example", "campaignname": MANDATORY,
                        "assignmentstatus": "In Progress"}},
    ]
    users = _parse_training(records, [MANDATORY, OPTIONAL])
    assert set(users.keys()) == {"a@acme.example", "b@acme.example"}
    # Untracked campaign is dropped
    assert list(users["a@acme.example"]["campaigns"].keys()) == [MANDATORY]
    assert users["a@acme.example"]["campaigns"][MANDATORY]["completed"] is True
    assert users["a@acme.example"]["campaigns"][MANDATORY]["date"] == "2026-05-01"
    assert users["b@acme.example"]["campaigns"][MANDATORY]["completed"] is False


def _users():
    return {
        "ok@acme.example": {"email": "ok@acme.example", "campaigns": {
            MANDATORY: {"completed": True, "date": "2026-05-01"},
            OPTIONAL: {"completed": True, "date": "2026-05-10"}}},
        "partial@acme.example": {"email": "partial@acme.example", "campaigns": {
            MANDATORY: {"completed": False, "date": ""},
            OPTIONAL: {"completed": True, "date": "2026-05-02"}}},
        "ext@other.com": {"email": "ext@other.com", "campaigns": {
            MANDATORY: {"completed": True, "date": "2026-04-01"}}},
    }


def test_access_payload_domain_and_mandatory_filter():
    payload = _build_access_payload(_users(), _cfg())
    emails = {p["email"] for p in payload}
    # ok@acme.example: domain + mandatory done -> included
    assert "ok@acme.example" in emails
    # partial@acme.example: domain but mandatory NOT done -> excluded
    assert "partial@acme.example" not in emails
    # ext@other.com: mandatory done but OUT of domain -> excluded
    assert "ext@other.com" not in emails
    entry = next(p for p in payload if p["email"] == "ok@acme.example")
    assert entry["completed"] is True
    assert entry["completion_date"] == "2026-05-01"
    assert MANDATORY in entry["justification"]


def test_access_payload_empty_when_no_mandatory():
    cfg = _cfg()
    cfg["mandatory_campaigns"] = []
    assert _build_access_payload(_users(), cfg) == []


def test_reporting_is_tenant_wide_per_campaign():
    rep = _build_reporting(_users(), _cfg())
    # 3 users total (tenant — NO domain filter); 2 completed the mandatory
    assert rep["users_total"] == 3
    assert rep["users_compliant"] == 2  # ok@ + ext@ (ext is tenant-wide)
    assert rep["overall_completion_pct"] == round(100 * 2 / 3, 1)
    camps = {c["name"]: c for c in rep["campaigns"]}
    assert camps[MANDATORY]["assigned"] == 3
    assert camps[MANDATORY]["completed"] == 2
    assert camps[MANDATORY]["overdue"] == 1
    # partial@acme.example is the only overdue on the mandatory campaign
    assert rep["overdue_total"] == 1
    assert rep["overdue"][0]["email"] == "partial@acme.example"
    assert MANDATORY in rep["overdue"][0]["missing"]
