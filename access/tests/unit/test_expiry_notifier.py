"""FEAT-42 — pure-core tests for the SA expiry notifier.

Exercises compute_expiry_hits (threshold crossing, idempotence, re-arming on
date change, catch-up after downtime) and resolve_recipients (owner → reviewer
fallback) without a database, exactly like compliance's test_proof_notifier.
"""
from datetime import date
from types import SimpleNamespace

from src.expiry_notifier import (THRESHOLDS, build_alert_html,
                                 compute_expiry_hits, resolve_recipients)

TODAY = date(2026, 9, 5)


def _sa(id="SVC-001", exp="", app="APP-001", **kw):
    return SimpleNamespace(id=id, name=id, application_id=app,
                           date_expiration=exp, secret_storage="vault", **kw)


def _app(id="APP-001", owner="", reviewers=None):
    return SimpleNamespace(id=id, nom="App " + id, owner_email=owner,
                           reviewers=reviewers or [])


def _user(id, email):
    return SimpleNamespace(id=id, email=email)


# ── compute_expiry_hits ─────────────────────────────────────────


def test_no_expiry_date_no_hit():
    assert compute_expiry_hits([_sa(exp="")], TODAY, {}) == []


def test_invalid_date_no_hit():
    assert compute_expiry_hits([_sa(exp="not-a-date")], TODAY, {}) == []


def test_far_future_no_hit():
    assert compute_expiry_hits([_sa(exp="2027-09-05")], TODAY, {}) == []


def test_threshold_30_crossed():
    hits = compute_expiry_hits([_sa(exp="2026-10-01")], TODAY, {})  # 26 days
    assert len(hits) == 1
    assert hits[0]["threshold"] == 30
    assert hits[0]["days_left"] == 26


def test_tightest_threshold_wins():
    hits = compute_expiry_hits([_sa(exp="2026-09-10")], TODAY, {})  # 5 days
    assert hits[0]["threshold"] == 7


def test_day_before_expiry_threshold_1():
    hits = compute_expiry_hits([_sa(exp="2026-09-06")], TODAY, {})  # 1 day
    assert hits[0]["threshold"] == 1


def test_expired_account_still_hits_threshold_1():
    # Notifier was down when J-1 passed: negative days still cross threshold 1.
    hits = compute_expiry_hits([_sa(exp="2026-09-01")], TODAY, {})
    assert hits[0]["threshold"] == 1
    assert hits[0]["days_left"] < 0


def test_sent_threshold_not_repeated():
    state = {"SVC-001": {"date": "2026-10-01", "sent": [30]}}
    assert compute_expiry_hits([_sa(exp="2026-10-01")], TODAY, state) == []


def test_next_threshold_fires_after_earlier_one_sent():
    state = {"SVC-001": {"date": "2026-09-10", "sent": [30, 15]}}
    hits = compute_expiry_hits([_sa(exp="2026-09-10")], TODAY, state)  # 5 days
    assert len(hits) == 1
    assert hits[0]["threshold"] == 7


def test_date_change_rearms_thresholds():
    # Alert for the OLD date was sent; pushing the date out then reaching a
    # threshold again must re-alert.
    state = {"SVC-001": {"date": "2026-09-10", "sent": [30, 15, 7, 1]}}
    hits = compute_expiry_hits([_sa(exp="2026-09-20")], TODAY, state)  # 15 days
    assert len(hits) == 1
    assert hits[0]["threshold"] == 15


def test_thresholds_constant_matches_spec():
    assert THRESHOLDS == (30, 15, 7, 1)


# ── resolve_recipients ──────────────────────────────────────────


def test_owner_email_is_primary_recipient():
    apps = {"APP-001": _app(owner="owner@corp.io", reviewers=["U1"])}
    users = {"U1": _user("U1", "rev@corp.io")}
    assert resolve_recipients(_sa(), apps, users) == ["owner@corp.io"]


def test_reviewers_fallback_when_no_owner():
    apps = {"APP-001": _app(owner="", reviewers=["U1", "U2"])}
    users = {"U1": _user("U1", "rev1@corp.io"), "U2": _user("U2", "")}
    assert resolve_recipients(_sa(), apps, users) == ["rev1@corp.io"]


def test_reviewers_raw_emails_pilot_directory_mode():
    apps = {"APP-001": _app(owner="", reviewers=["dir@corp.io", "U1"])}
    users = {"U1": _user("U1", "rev1@corp.io")}
    assert resolve_recipients(_sa(), apps, users) == ["dir@corp.io", "rev1@corp.io"]


def test_invalid_owner_falls_back_to_reviewers():
    apps = {"APP-001": _app(owner="not-an-email", reviewers=["U1"])}
    users = {"U1": _user("U1", "rev1@corp.io")}
    assert resolve_recipients(_sa(), apps, users) == ["rev1@corp.io"]


def test_no_app_no_recipients():
    assert resolve_recipients(_sa(app="APP-MISSING"), {}, {}) == []


def test_no_owner_no_reviewer_email_empty():
    apps = {"APP-001": _app(owner="", reviewers=["U1"])}
    users = {"U1": _user("U1", "")}
    assert resolve_recipients(_sa(), apps, users) == []


def test_recipients_deduplicated():
    apps = {"APP-001": _app(owner="", reviewers=["a@corp.io", "A@corp.io"])}
    assert resolve_recipients(_sa(), apps, {}) == ["a@corp.io"]


# ── build_alert_html ────────────────────────────────────────────


def test_alert_html_lists_account_and_app():
    sa = _sa(exp="2026-09-10")
    apps = {"APP-001": _app()}
    html = build_alert_html([{"sa": sa, "days_left": 5, "threshold": 7}], apps, TODAY)
    assert "SVC-001" in html
    assert "App APP-001" in html
    assert "expire dans 5 jour(s)" in html  # default language: fr


def test_alert_html_english(monkeypatch):
    # Module-level language switch (ACCESS_MAIL_LANG) — same pattern as the
    # Pilot deadline digest. English body and states.
    import src.expiry_notifier as mod
    monkeypatch.setattr(mod, "MAIL_LANG", "en")
    sa = _sa(exp="2026-09-10")
    html = build_alert_html([{"sa": sa, "days_left": 5, "threshold": 7}],
                            {"APP-001": _app()}, TODAY)
    assert "expires in 5 day(s)" in html
    assert "about to expire" in html
    assert "expire dans" not in html


def test_alert_html_unknown_lang_falls_back_to_french(monkeypatch):
    import src.expiry_notifier as mod
    monkeypatch.setattr(mod, "MAIL_LANG", "de")
    sa = _sa(exp="2026-09-10")
    html = build_alert_html([{"sa": sa, "days_left": 5, "threshold": 7}],
                            {"APP-001": _app()}, TODAY)
    assert "expire dans 5 jour(s)" in html


def test_alert_html_expired_state():
    sa = _sa(exp="2026-09-01")
    html = build_alert_html([{"sa": sa, "days_left": -4, "threshold": 1}],
                            {"APP-001": _app()}, TODAY)
    assert "expiré" in html


def test_alert_html_escapes_user_controlled_names():
    # Account/application names are user input — they must never reach the
    # email HTML unescaped (stored-XSS/phishing via the alert email).
    sa = _sa(exp="2026-09-10")
    sa.name = "<img src=x onerror=alert(1)>"
    app = _app()
    app.nom = "<script>evil()</script>"
    html = build_alert_html([{"sa": sa, "days_left": 5, "threshold": 7}],
                            {"APP-001": app}, TODAY)
    assert "<img" not in html and "<script>" not in html
    assert "&lt;img" in html and "&lt;script&gt;" in html
