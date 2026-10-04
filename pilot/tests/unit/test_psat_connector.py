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
        "email_domains": ["acme.example"],
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


def test_access_payload_domain_filter_and_full_snapshot():
    # Current semantics (awareness-sync): ALL users of the domain, with
    # the full record of their trainings (incomplete ones included) —
    # Access owns the compliance state machine. The old version pushed only
    # the compliant ones; the tests had stayed on that behavior.
    payload = _build_access_payload(_users(), _cfg(), today="2026-06-01")
    emails = {p["email"] for p in payload}
    assert "ok@acme.example" in emails
    assert "partial@acme.example" in emails      # domain ok, full snapshot
    assert "ext@other.com" not in emails         # outside the domain
    entry = next(p for p in payload if p["email"] == "ok@acme.example")
    done = {t["campaign"]: t for t in entry["trainings"]}
    assert done[MANDATORY]["completed"] is True
    assert done[MANDATORY]["completion_date"] == "2026-05-01"
    partial = next(p for p in payload if p["email"] == "partial@acme.example")
    mand = next(t for t in partial["trainings"] if t["campaign"] == MANDATORY)
    assert mand["completed"] is False


def test_access_payload_empty_without_domains_matching():
    cfg = _cfg()
    cfg["email_domains"] = ["nowhere.invalid"]
    assert _build_access_payload(_users(), cfg, today="2026-06-01") == []


def test_reporting_is_tenant_wide_per_campaign():
    cfg = _cfg()
    rep = _build_reporting(_users(), cfg["tracked_campaigns"],
                           cfg["mandatory_campaigns"], today="2026-06-01")
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


# ---------- FEAT-53: per-user snapshot behind the CSV export -------------- #

from src.connectors.proofpoint_psat import _assignment_status, _build_assignments  # noqa: E402


def test_parse_training_collects_names_sent_date_and_excluded_users():
    records = [
        # A curriculum: two module rows for the same user, one completed.
        {"attributes": {"useremailaddress": "a@acme.example", "userfirstname": "Alice",
                        "userlastname": "Martin", "assignmentname": MANDATORY,
                        "userassignmentstatus": "Not Started", "assignmentstartdate": "2026-03-01",
                        "assignmentduedate": "2026-04-01"}},
        {"attributes": {"useremailaddress": "a@acme.example", "assignmentname": MANDATORY,
                        "userassignmentstatus": "Overdue - Completed", "assignmentstartdate": "2026-02-15",
                        "completiondate": "2026-04-10T09:00:00Z", "assignmentduedate": "2026-04-01"}},
        {"attributes": {"useremailaddress": "gone@acme.example", "assignmentname": MANDATORY,
                        "userassignmentstatus": "Not Started", "useractiveflag": "false"}},
    ]
    excluded: dict = {}
    users = _parse_training(records, [MANDATORY], excluded)
    a = users["a@acme.example"]
    assert (a["first_name"], a["last_name"]) == ("Alice", "Martin")
    c = a["campaigns"][MANDATORY]
    assert (c["completed"], c["sent"], c["date"], c["due"]) == (True, "2026-02-15", "2026-04-10", "2026-04-01")
    assert c["psat_status"] == "Overdue - Completed"
    # Excluded users stay out of the counted set, collected aside.
    assert "gone@acme.example" not in users and "gone@acme.example" in excluded
    # Without the collector they are simply dropped (KPI behaviour unchanged).
    assert "gone@acme.example" not in _parse_training(records, [MANDATORY])


def test_assignment_status_follows_the_kpi_rules():
    today = "2026-05-01"
    assert _assignment_status({"completed": True, "date": "2026-03-01", "due": "2026-04-01"}, today) == "completed"
    assert _assignment_status({"completed": True, "date": "2026-04-10", "due": "2026-04-01"}, today) == "completed_late"
    assert _assignment_status({"completed": False, "due": "2026-04-01"}, today) == "overdue"
    assert _assignment_status({"completed": False, "due": "2026-06-01"}, today) == "pending"
    assert _assignment_status({"completed": False, "due": ""}, today) == "pending"
    assert _assignment_status({"completed": True, "date": "2026-03-01"}, today, excluded=True) == "excluded"


def test_build_assignments_matches_the_kpi_counts():
    users = _users()
    excluded = {"gone@acme.example": {"email": "gone@acme.example", "campaigns": {
        MANDATORY: {"completed": False}}},
        # Counted through another row for the same campaign: not listed twice.
        "ok@acme.example": {"email": "ok@acme.example", "campaigns": {MANDATORY: {"completed": False}}}}
    rows = _build_assignments(users, excluded, [MANDATORY], "2026-06-01")
    mine = [r for r in rows if r["campaign"] == MANDATORY]
    assert len(rows) == len(mine) == 4           # OPTIONAL is not an effective campaign
    counted = [r for r in mine if r["status"] != "excluded"]
    done = [r for r in counted if r["status"] in ("completed", "completed_late")]
    rep = _build_reporting(users, [MANDATORY], [MANDATORY], "2026-06-01")["campaigns"][0]
    assert (len(counted), len(done)) == (rep["assigned"], rep["completed"])
    assert [r["email"] for r in mine if r["status"] == "excluded"] == ["gone@acme.example"]
    assert next(r for r in mine if r["email"] == "partial@acme.example")["completion_date"] == ""


# ---------- BUG-80: an empty filter follows every training ----------------- #

def test_empty_filter_discovers_every_current_training():
    from src.connectors.proofpoint_psat import _discover_campaigns
    meta = {
        "Phishing Q3": {"due": "2026-09-30", "start": "2026-07-01", "active": True},
        "Onboarding": {"due": "", "start": "2026-01-01", "active": True},
        "Archived": {"due": "2026-09-30", "start": "2026-07-01", "active": False},
        "Next year": {"due": "2027-03-01", "start": "2027-01-01", "active": True},
        "Old": {"due": "2024-01-01", "start": "2023-12-01", "active": True},
    }
    assert _discover_campaigns(meta, "", "2026-10-04") == ["Onboarding", "Phishing Q3"]
    assert _discover_campaigns(meta, "phish", "2026-10-04") == ["Phishing Q3"]


def test_live_campaigns_follow_list_filter_or_everything():
    from src.connectors.proofpoint_psat import _live_campaigns
    meta = {"Phishing Q3": {"due": "2026-09-30", "start": "2026-07-01", "active": True},
            "Onboarding": {"due": "", "start": "2026-01-01", "active": True}}
    cfg = {"tracked_campaigns": [], "campaign_filter": "", "retention_months": 12}
    assert _live_campaigns(cfg, meta, "2026-10-04") == (["Onboarding", "Phishing Q3"], "")
    assert _live_campaigns({**cfg, "campaign_filter": "phish"}, meta, "2026-10-04") == (["Phishing Q3"], "")
    assert _live_campaigns({**cfg, "tracked_campaigns": ["X"]}, meta, "2026-10-04") == (["X"], "")
    # A filter is set: it drives the discovery even when a list exists.
    assert _live_campaigns({**cfg, "tracked_campaigns": ["X"], "campaign_filter": "phish"},
                           meta, "2026-10-04") == (["Phishing Q3"], "")
    assert _live_campaigns(cfg, {}, "2026-10-04") == ([], "aucune formation en cours dans PSAT")
    assert _live_campaigns({**cfg, "campaign_filter": "zz"}, meta, "2026-10-04")[1].startswith("aucune formation en cours ne correspond")
