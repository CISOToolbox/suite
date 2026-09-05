"""Service-account expiry alerts (FEAT-42).

Emails the owner of the application a service account belongs to when the
account's ``date_expiration`` approaches: one alert per threshold crossed
among J-30, J-15, J-7 and J-1. Recipients fall back from the application's
``owner_email`` to the perimeter's reviewers (SiUser ids resolved to emails,
or raw Pilot-directory emails); with no resolvable recipient, no email goes
out — the Pilot dashboard alert (``sa_expiring_soon`` in /internal/stats)
still surfaces the situation.

Design mirrors compliance/src/proof_notifier.py: an in-process asyncio loop
whose cadence is gated by an ``app_settings`` row (``sa_expiry.last_run``) so
it survives restarts and never depends on an external cron.

Idempotence: which thresholds were already notified is remembered per
``(service-account id, date_expiration)`` in the ``app_settings`` row
``sa_expiry.sent`` (JSON). Changing an account's expiry date re-arms every
threshold; a notifier that was down while a threshold passed catches up (a
threshold counts as crossed for any ``days_left <= threshold``, negatives
included).

Delivery is at-least-ONE per threshold, not at-least-once per recipient:
when a hit fans out to several recipients (owner absent, multiple
reviewers) and only some sends succeed, the threshold is recorded as sent —
the failed recipients are not retried for that threshold (they catch the
next one). The primary design has a single recipient (owner_email), where
this distinction vanishes.

The computation core (``compute_expiry_hits``, ``resolve_recipients``) is
pure and DB-free — exercised directly by tests/unit/test_expiry_notifier.py.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import date, datetime, timezone
from html import escape

from sqlalchemy import select

from src.database import async_session
from src.mailer import send_smtp
from src.models import AppSettings, Application, ServiceAccount, SiUser

logger = logging.getLogger("access-expiry")

# Alert thresholds, days before expiry (FEAT-42: J-30, J-15, J-7, J-1).
THRESHOLDS = (30, 15, 7, 1)

TICK_SECONDS = int(os.getenv("ACCESS_EXPIRY_TICK_SECONDS", "3600"))
INTERVAL_HOURS = int(os.getenv("ACCESS_EXPIRY_INTERVAL_HOURS", "24"))

# Alert-email language — module-level, like the other suite mailers (the
# recipients are plain emails with no stored preference). Same FR/EN dict
# pattern as pilot/src/deadline_digest.py; default fr, override with
# ACCESS_MAIL_LANG=en.
MAIL_LANG = os.getenv("ACCESS_MAIL_LANG", "fr")

_L = {
    "fr": {
        "subject_expired": "[CISO Toolbox] {n} compte(s) de service expiré(s)",
        "subject_soon": "[CISO Toolbox] {n} compte(s) de service expirant sous {d} jour(s)",
        "intro": "Les comptes de service suivants arrivent à expiration :",
        "col_account": "Compte", "col_app": "Application",
        "col_expiry": "Expiration", "col_state": "État",
        "expired": "expiré", "in_days": "expire dans {d} jour(s)",
        "footer": ("Renouvelez le secret ou prolongez le compte dans le module "
                   "Access, puis mettez à jour sa date d'expiration."),
    },
    "en": {
        "subject_expired": "[CISO Toolbox] {n} expired service account(s)",
        "subject_soon": "[CISO Toolbox] {n} service account(s) expiring within {d} day(s)",
        "intro": "The following service accounts are about to expire:",
        "col_account": "Account", "col_app": "Application",
        "col_expiry": "Expiry", "col_state": "State",
        "expired": "expired", "in_days": "expires in {d} day(s)",
        "footer": ("Renew the secret or extend the account in the Access "
                   "module, then update its expiry date."),
    },
}


def _lang() -> dict:
    return _L.get(MAIL_LANG) or _L["fr"]

_STATE_KEY = "sa_expiry.sent"
_LAST_RUN_KEY = "sa_expiry.last_run"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_email(v: str | None) -> bool:
    return bool(v and _EMAIL_RE.match(v.strip()))


# ── Pure core ───────────────────────────────────────────────────


def compute_expiry_hits(sas: list, today: date, sent_state: dict) -> list[dict]:
    """Return one hit per service account whose tightest crossed threshold has
    not been notified yet for its current expiry date.

    ``sent_state`` maps sa_id -> {"date": iso, "sent": [thresholds]}. A hit is
    {"sa": <ServiceAccount-like>, "days_left": int, "threshold": int}.
    """
    hits: list[dict] = []
    for sa in sas:
        exp_raw = (getattr(sa, "date_expiration", "") or "").strip()
        if not exp_raw:
            continue
        try:
            exp = date.fromisoformat(exp_raw)
        except (ValueError, TypeError):
            continue
        days_left = (exp - today).days
        crossed = [t for t in THRESHOLDS if days_left <= t]
        if not crossed:
            continue
        threshold = min(crossed)  # the tightest active threshold
        entry = sent_state.get(sa.id) or {}
        already = set(entry.get("sent") or []) if entry.get("date") == exp_raw else set()
        if threshold in already:
            continue
        hits.append({"sa": sa, "days_left": days_left, "threshold": threshold})
    return hits


def resolve_recipients(sa, apps_by_id: dict, users_by_id: dict) -> list[str]:
    """Owner email of the SA's application; else reviewer emails; else []."""
    app = apps_by_id.get(getattr(sa, "application_id", "") or "")
    if app is None:
        return []
    owner = (getattr(app, "owner_email", "") or "").strip()
    if _is_email(owner):
        return [owner]
    out: list[str] = []
    for rid in (getattr(app, "reviewers", None) or []):
        rid = str(rid).strip()
        if _is_email(rid):
            out.append(rid)  # Pilot-directory mode stores raw emails
            continue
        su = users_by_id.get(rid)
        email = (getattr(su, "email", "") or "").strip() if su is not None else ""
        if _is_email(email):
            out.append(email)
    # de-duplicate, keep order
    seen: set[str] = set()
    return [r for r in out if not (r.lower() in seen or seen.add(r.lower()))]


def build_alert_html(items: list[dict], apps_by_id: dict, today: date) -> str:
    L = _lang()
    rows = ""
    for it in sorted(items, key=lambda x: x["days_left"]):
        sa = it["sa"]
        app = apps_by_id.get(getattr(sa, "application_id", "") or "")
        state = (L["expired"] if it["days_left"] < 0
                 else L["in_days"].format(d=it["days_left"]))
        # Account/application names are user-controlled — escape everything
        # interpolated into the email HTML (stored-XSS/phishing vector).
        rows += (
            "<tr>"
            f"<td style='padding:4px 10px'>{escape(str(sa.name or sa.id))}</td>"
            f"<td style='padding:4px 10px'>{escape(str(getattr(app, 'nom', '') or '-'))}</td>"
            f"<td style='padding:4px 10px'>{escape(str(sa.date_expiration))}</td>"
            f"<td style='padding:4px 10px'><strong>{escape(state)}</strong></td>"
            "</tr>"
        )
    return (
        f"<p>{L['intro']}</p>"
        "<table style='border-collapse:collapse'>"
        f"<tr><th style='padding:4px 10px;text-align:left'>{L['col_account']}</th>"
        f"<th style='padding:4px 10px;text-align:left'>{L['col_app']}</th>"
        f"<th style='padding:4px 10px;text-align:left'>{L['col_expiry']}</th>"
        f"<th style='padding:4px 10px;text-align:left'>{L['col_state']}</th></tr>"
        f"{rows}</table>"
        f"<p>{L['footer']}</p>"
    )


# ── DB-bound runner ─────────────────────────────────────────────


async def _get_setting(db, key: str) -> str | None:
    row = await db.get(AppSettings, key)
    return row.value if row else None


async def _set_setting(db, key: str, value: str) -> None:
    row = await db.get(AppSettings, key)
    if row is None:
        db.add(AppSettings(key=key, value=value))
    else:
        row.value = value


def _load_state(raw: str | None) -> dict:
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}


async def run_now(db) -> dict:
    """Run an expiry check immediately (no cadence gate). Returns a summary.

    Does not commit — the caller owns the transaction. Only thresholds that
    were actually emailed are recorded as sent, so an account whose
    application gains an owner later still gets its pending alert.
    """
    today = datetime.now(timezone.utc).date()
    sas = (await db.execute(select(ServiceAccount))).scalars().all()
    apps = (await db.execute(select(Application))).scalars().all()
    users = (await db.execute(select(SiUser))).scalars().all()
    apps_by_id = {a.id: a for a in apps}
    users_by_id = {u.id: u for u in users}

    state = _load_state(await _get_setting(db, _STATE_KEY))

    # Prune state entries whose account is gone, on EVERY run — the row must
    # not grow forever on a quiet system where nothing gets sent.
    live_ids = {s.id for s in sas}
    pruned = {k: v for k, v in state.items() if k in live_ids}
    if pruned != state:
        state = pruned
        await _set_setting(db, _STATE_KEY, json.dumps(state, sort_keys=True))

    hits = compute_expiry_hits(sas, today, state)
    if not hits:
        return {"hits": 0, "sent": [], "errors": [], "unreachable": 0}

    # Group hits per recipient — one email per recipient per run.
    per_recipient: dict[str, list[dict]] = {}
    unreachable = 0
    for hit in hits:
        recipients = resolve_recipients(hit["sa"], apps_by_id, users_by_id)
        if not recipients:
            unreachable += 1
            continue
        for r in recipients:
            per_recipient.setdefault(r, []).append(hit)

    sent_to: list[str] = []
    errors: list[dict] = []
    notified: set[tuple[str, int]] = set()
    for recipient, items in per_recipient.items():
        html = build_alert_html(items, apps_by_id, today)
        nearest = min(it["days_left"] for it in items)
        L = _lang()
        subject = (L["subject_expired"].format(n=len(items)) if nearest < 0
                   else L["subject_soon"].format(n=len(items), d=nearest))
        ok, err = await asyncio.to_thread(send_smtp, recipient, subject, html)
        if ok:
            sent_to.append(recipient)
            for it in items:
                notified.add((it["sa"].id, it["threshold"]))
        else:
            errors.append({"to": recipient, "error": err})

    if notified:
        for sa_id, threshold in notified:
            sa = next((s for s in sas if s.id == sa_id), None)
            exp_raw = (getattr(sa, "date_expiration", "") or "").strip()
            entry = state.get(sa_id) or {}
            if entry.get("date") != exp_raw:
                entry = {"date": exp_raw, "sent": []}
            if threshold not in entry["sent"]:
                entry["sent"].append(threshold)
            state[sa_id] = entry
        await _set_setting(db, _STATE_KEY, json.dumps(state, sort_keys=True))

    return {"hits": len(hits), "sent": sent_to, "errors": errors,
            "unreachable": unreachable}


async def _maybe_run() -> None:
    async with async_session() as db:
        now = datetime.now(timezone.utc)
        last = await _get_setting(db, _LAST_RUN_KEY)
        if last:
            try:
                if (now - datetime.fromisoformat(last)).total_seconds() < INTERVAL_HOURS * 3600:
                    return
            except ValueError:
                pass
        result = await run_now(db)
        await _set_setting(db, _LAST_RUN_KEY, now.isoformat())
        await db.commit()
        if result.get("sent") or result.get("errors"):
            logger.info("sa-expiry check: %s", result)


async def run_scheduler() -> None:
    await asyncio.sleep(15)  # let the DB warm up
    logger.info("sa-expiry scheduler started (tick=%ds, interval=%dh, thresholds=%s)",
                TICK_SECONDS, INTERVAL_HOURS, THRESHOLDS)
    while True:
        try:
            await _maybe_run()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("sa-expiry tick failed")
        await asyncio.sleep(TICK_SECONDS)
