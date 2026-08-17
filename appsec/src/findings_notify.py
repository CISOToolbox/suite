"""FEAT-35 — findings email notifications (new-findings alert + weekly recap).

WHO is notified comes from ``Application.notification_emails`` (per-app
recipient list, [] = silence). HOW each recipient is notified comes from
their per-user notification preferences — stored in Pilot in suite mode
(bulk-resolved here via the internal lookup API), or in the local
``notification_prefs`` table in standalone. Recipients without an account
get the defaults (everything, Monday, the app's configured language).

Send discipline is the Watch/Pilot pattern: every attempt writes a
``DigestRun`` row, the unique (recipient, kind, period_key) makes the
per-scan alert and the weekly recap idempotent, empty content is
journalised ``skipped_empty`` and not sent, bodies are archived.
"""
from __future__ import annotations

import asyncio
import html as _html
import logging
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session
from src.models import Application, DigestRun, Finding, NotificationPrefs, ScanJob, User

logger = logging.getLogger("appsec-notify")

_TICK_SECONDS = 3600
_INITIAL_DELAY = 180
_SEND_HOUR_UTC = 8
_WEEKLY_TOP_CAP = 15
_OPEN_STATUSES = ("new", "to_fix")

PILOT_URL = os.getenv("PILOT_URL", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

APPSEC_PREF_DEFAULTS = {"alert_enabled": True, "alert_min_severity": "low",
                        "weekly_enabled": True, "weekly_day": 0,
                        "weekly_min_severity": "low",
                        "subject_prefix": "[AppSec]"}

_task: asyncio.Task | None = None


# ── per-recipient preference resolution ──────────────────────────────────

def severity_passes(severity: str, minimum: str) -> bool:
    """True when ``severity`` is at least ``minimum`` (unknown severities
    are treated as low so they are only dropped by an explicit floor)."""
    s = _SEV_ORDER.get((severity or "").lower(), 3)
    m = _SEV_ORDER.get((minimum or "low").lower(), 3)
    return s <= m


def appsec_prefs_of(full_prefs: dict | None) -> dict:
    """Extract the appsec block of a full prefs payload, defaults applied."""
    out = dict(APPSEC_PREF_DEFAULTS)
    block = ((full_prefs or {}).get("module_prefs") or {}).get("appsec") or {}
    for k in out:
        if k in block:
            out[k] = block[k]
    out["lang"] = (full_prefs or {}).get("lang") or ""
    return out


async def resolve_recipient_prefs(db: AsyncSession, emails: list[str]) -> dict[str, dict]:
    """email(lower) → appsec prefs (+lang). Suite mode asks Pilot (single
    storage); standalone reads the local table. Unknown emails are absent —
    callers apply APPSEC_PREF_DEFAULTS."""
    emails = [e.strip().lower() for e in emails if e and e.strip()]
    if not emails:
        return {}
    if PILOT_URL and SERVICE_TOKEN:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    PILOT_URL.rstrip("/") + "/api/internal/notification-prefs/lookup",
                    headers={"X-Service-Token": SERVICE_TOKEN},
                    json={"emails": emails})
            if resp.is_success:
                return {k.lower(): appsec_prefs_of(v) for k, v in resp.json().items()}
            logger.warning("pilot prefs lookup failed: HTTP %s", resp.status_code)
        except httpx.HTTPError as exc:
            logger.warning("pilot prefs lookup unreachable: %s", exc)
        return {}
    rows = (await db.execute(
        select(User, NotificationPrefs)
        .join(NotificationPrefs, NotificationPrefs.user_id == User.id)
        .where(func.lower(User.email).in_(emails))
    )).all()
    return {u.email.lower(): appsec_prefs_of(
        {"module_prefs": p.module_prefs or {}, "lang": p.lang}) for u, p in rows}


# ── rendering ────────────────────────────────────────────────────────────

_L = {
    "fr": {
        "alert_subject": "{prefix} {app} — {n} nouveau(x) finding(s)",
        "weekly_subject": "{prefix} Récap hebdo — {n} finding(s) ouvert(s)",
        "hello": "Bonjour,",
        "alert_intro": "Le scan {scanner} de l'application {app} a découvert de nouveaux findings :",
        "weekly_intro": "Voici l'état hebdomadaire des findings ouverts sur vos applications :",
        "open_by_sev": "Ouverts par sévérité",
        "trend": "Sur 7 jours : {new} nouveau(x), {fixed} corrigé(s)",
        "top": "Principaux findings ouverts",
        "open_app": "Ouvrir dans AppSec",
        "footer_alert": "Vous recevez cet email car votre adresse figure dans les destinataires de notification de cette application (AppSec). Vos seuils se règlent dans le menu Notifications (cloche).",
        "footer_weekly": "Vous recevez ce récapitulatif car votre adresse figure dans les destinataires de notification d'au moins une application AppSec. Jour d'envoi et seuils se règlent dans le menu Notifications (cloche).",
    },
    "en": {
        "alert_subject": "{prefix} {app} — {n} new finding(s)",
        "weekly_subject": "{prefix} Weekly recap — {n} open finding(s)",
        "hello": "Hello,",
        "alert_intro": "The {scanner} scan of application {app} discovered new findings:",
        "weekly_intro": "Here is the weekly status of open findings on your applications:",
        "open_by_sev": "Open by severity",
        "trend": "Last 7 days: {new} new, {fixed} fixed",
        "top": "Top open findings",
        "open_app": "Open in AppSec",
        "footer_alert": "You receive this email because your address is listed as a notification recipient of this application (AppSec). Thresholds are configured in the Notifications menu (bell).",
        "footer_weekly": "You receive this recap because your address is listed as a notification recipient of at least one AppSec application. Send day and thresholds are configured in the Notifications menu (bell).",
    },
}

_SEV_COLORS = {"critical": "#c0392b", "high": "#e67e22",
               "medium": "#f1c40f", "low": "#95a5a6"}


def _base_url() -> str:
    return os.getenv("PUBLIC_BASE_URL", "").rstrip("/")


def _app_link(lang_pack: dict, app_id: str) -> str:
    base = _base_url()
    if not base:
        return ""
    url = base + "/appsec/?app=" + app_id + "#findings"
    return '<p><a href="' + _html.escape(url) + '" style="color:#2563eb">' \
        + _html.escape(lang_pack["open_app"]) + " ↗</a></p>"


def _findings_table(rows: list[Finding]) -> str:
    e = _html.escape
    h = '<table style="border-collapse:collapse;width:100%;background:#fff">'
    for f in rows:
        color = _SEV_COLORS.get((f.severity or "").lower(), "#bdc3c7")
        h += ('<tr style="border-bottom:1px solid #e5e7eb">'
              '<td style="padding:6px 10px;white-space:nowrap;color:' + color
              + ';font-weight:700;text-transform:uppercase;font-size:12px">' + e(f.severity or "?") + "</td>"
              '<td style="padding:6px 10px">' + e(f.title or "") + "</td>"
              '<td style="padding:6px 10px;font-family:monospace;font-size:12px;color:#6b7280">'
              + e(f.cve_id or f.type or "") + "</td>"
              '<td style="padding:6px 10px;font-family:monospace;font-size:12px;color:#6b7280">'
              + e((f.target or "")[:80]) + "</td></tr>")
    return h + "</table>"


def _sev_counters(counts: dict[str, int]) -> str:
    e = _html.escape
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        n = counts.get(sev, 0)
        if n:
            parts.append('<span style="color:' + _SEV_COLORS[sev]
                         + ';font-weight:700">' + str(n) + " " + e(sev) + "</span>")
    return " · ".join(parts) or "0"


def _wrap(body: str) -> str:
    return ('<!doctype html><html><body style="font-family:Arial,sans-serif;color:#222;'
            'line-height:1.5;background:#f5f5f5;margin:0;padding:0">'
            '<div style="max-width:760px;margin:0 auto;padding:24px">' + body + "</div></body></html>")


def render_alert_html(app: Application, scanner: str, findings: list[Finding], lang: str) -> str:
    L = _L.get(lang) or _L["en"]
    e = _html.escape
    counts: dict[str, int] = {}
    for f in findings:
        counts[(f.severity or "").lower()] = counts.get((f.severity or "").lower(), 0) + 1
    body = "<p>" + e(L["hello"]) + "</p>"
    body += "<p>" + e(L["alert_intro"].format(scanner=scanner, app=app.name)) + "</p>"
    body += "<p>" + _sev_counters(counts) + "</p>"
    body += _findings_table(sorted(findings, key=lambda f: _SEV_ORDER.get((f.severity or "").lower(), 3)))
    body += _app_link(L, str(app.id))
    body += '<p style="margin-top:26px;font-size:12px;color:#7f8c8d">' + e(L["footer_alert"]) + "</p>"
    return _wrap(body)


def render_weekly_html(sections: list[dict], lang: str) -> str:
    """sections: [{app, counts, top (Finding list), new7, fixed7}]"""
    L = _L.get(lang) or _L["en"]
    e = _html.escape
    body = "<p>" + e(L["hello"]) + "</p><p>" + e(L["weekly_intro"]) + "</p>"
    for s in sections:
        app = s["app"]
        body += ('<h2 style="color:#2c3e50;border-bottom:2px solid #64748b;'
                 'padding-bottom:6px;margin-top:28px">' + e(app.name) + "</h2>")
        body += "<p>" + e(L["open_by_sev"]) + " : " + _sev_counters(s["counts"]) + "<br>"
        body += e(L["trend"].format(new=s["new7"], fixed=s["fixed7"])) + "</p>"
        if s["top"]:
            body += "<p><strong>" + e(L["top"]) + "</strong></p>" + _findings_table(s["top"])
        body += _app_link(L, str(app.id))
    body += '<p style="margin-top:26px;font-size:12px;color:#7f8c8d">' + e(L["footer_weekly"]) + "</p>"
    return _wrap(body)


# ── delivery ─────────────────────────────────────────────────────────────

def _send_email(cfg: dict, recipient: str, subject: str, html: str) -> None:
    from src.mailer_common import smtp_deliver
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    sender = cfg.get("from_addr") or cfg.get("user") or ""
    msg["From"] = formataddr(("CISO Toolbox AppSec", sender))
    msg["To"] = recipient
    msg.attach(MIMEText(html, "html", "utf-8"))
    smtp_deliver(
        cfg.get("host", ""), int(cfg.get("port") or 587),
        use_tls=str(cfg.get("tls") or "true").lower() in ("1", "true", "yes"),
        username=cfg.get("user") or "", password=cfg.get("password") or "",
        sender=sender, recipients=[recipient], raw_message=msg.as_string(),
    )


def _smtp_cfg() -> dict:
    from src.routes.internal import _smtp_config
    return dict(_smtp_config)


async def _journal_and_send(db: AsyncSession, recipient: str, kind: str,
                            period_key: str, subject: str, html: str,
                            items: int) -> str:
    cfg = _smtp_cfg()
    status, err = "sent", ""
    if not cfg.get("host"):
        status, err = "failed", "SMTP not configured (push it from Pilot settings)"
    else:
        try:
            await asyncio.to_thread(_send_email, cfg, recipient, subject, html)
        except Exception as exc:
            status, err = "failed", str(exc)[:2000]
    db.add(DigestRun(id=uuid.uuid4(), recipient=recipient, kind=kind,
                     period_key=period_key, status=status, items_count=items,
                     error_message=err, body_html=html))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return "duplicate"
    logger.info("%s notification %s for %s (%s items)", kind, status, recipient, items)
    return status


# ── 1. new-findings alert (called at scan completion) ────────────────────

async def notify_scan_new_findings(db: AsyncSession, job: ScanJob) -> None:
    """One email per (scan, recipient) listing the findings first seen by
    this run, filtered by each recipient's severity floor. Never raises —
    a notification failure must not fail the scan."""
    try:
        app = await db.get(Application, job.application_id)
        if app is None or not (app.notification_emails or []):
            return
        new_rows = (await db.execute(
            select(Finding).where(
                Finding.application_id == app.id,
                Finding.scanner == job.scanner,
                Finding.status == "new",
                Finding.created_at >= (job.started_at or job.created_at),
            )
        )).scalars().all()
        if not new_rows:
            return
        prefs_map = await resolve_recipient_prefs(db, list(app.notification_emails))
        for email in app.notification_emails:
            key = email.strip().lower()
            if not key:
                continue
            prefs = prefs_map.get(key, dict(APPSEC_PREF_DEFAULTS))
            if not prefs.get("alert_enabled", True):
                continue
            visible = [f for f in new_rows
                       if severity_passes(f.severity, prefs.get("alert_min_severity", "low"))]
            if not visible:
                continue
            lang = prefs.get("lang") or app.notification_lang or "en"
            lang = lang if lang in ("fr", "en") else "en"
            html = render_alert_html(app, job.scanner, visible, lang)
            prefix = (prefs.get("subject_prefix") or "[AppSec]").strip()
            subject = (_L.get(lang) or _L["en"])["alert_subject"].format(prefix=prefix, app=app.name, n=len(visible))
            await _journal_and_send(db, key, "alert", str(job.id), subject, html, len(visible))
    except Exception:  # pragma: no cover — never fail the scan on notify
        logger.exception("new-findings notification crashed for job %s", job.id)
        try:
            await db.rollback()
        except Exception:
            pass


# ── 2. weekly recap ──────────────────────────────────────────────────────

def iso_week_key(d: date) -> str:
    y, w, _ = d.isocalendar()
    return f"{y}-W{w:02d}"


async def _weekly_sections(db: AsyncSession, apps: list[Application],
                           min_severity: str) -> tuple[list[dict], int]:
    since7 = datetime.now(timezone.utc) - timedelta(days=7)
    sections, total = [], 0
    for app in apps:
        rows = (await db.execute(
            select(Finding).where(
                Finding.application_id == app.id,
                Finding.status.in_(_OPEN_STATUSES),
            )
        )).scalars().all()
        rows = [f for f in rows if severity_passes(f.severity, min_severity)]
        if not rows:
            continue
        counts: dict[str, int] = {}
        for f in rows:
            counts[(f.severity or "").lower()] = counts.get((f.severity or "").lower(), 0) + 1
        top = sorted(rows, key=lambda f: (_SEV_ORDER.get((f.severity or "").lower(), 3),
                                          f.created_at or datetime.min.replace(tzinfo=timezone.utc)))
        new7 = sum(1 for f in rows if (f.created_at or since7) >= since7)
        fixed7 = (await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.application_id == app.id,
                Finding.status == "fixed",
                Finding.triaged_at.isnot(None),
                Finding.triaged_at >= since7,
            )
        )).scalar() or 0
        sections.append({"app": app, "counts": counts,
                         "top": top[:_WEEKLY_TOP_CAP], "new7": new7, "fixed7": fixed7})
        total += len(rows)
    return sections, total


async def send_weekly_for_recipient(db: AsyncSession, email: str,
                                    apps: list[Application], prefs: dict,
                                    *, week_key: str | None = None,
                                    force: bool = False) -> str:
    week = week_key or iso_week_key(date.today())
    if force:
        week = "t-" + uuid.uuid4().hex[:8]
    sections, total = await _weekly_sections(db, apps, prefs.get("weekly_min_severity", "low"))
    if not sections and not force:
        db.add(DigestRun(id=uuid.uuid4(), recipient=email, kind="weekly",
                         period_key=week, status="skipped_empty"))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
        return "skipped_empty"
    lang = prefs.get("lang") or (apps[0].notification_lang if apps else "en")
    lang = lang if lang in ("fr", "en") else "en"
    html = render_weekly_html(sections, lang)
    prefix = (prefs.get("subject_prefix") or "[AppSec]").strip()
    subject = (_L.get(lang) or _L["en"])["weekly_subject"].format(prefix=prefix, n=total)
    return await _journal_and_send(db, email, "weekly", week, subject, html, total)


async def tick_weekly(db: AsyncSession, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    if now.hour < _SEND_HOUR_UTC:
        return 0
    today = now.date()
    week = iso_week_key(today)

    apps = (await db.execute(
        select(Application).where(Application.enabled.is_(True))
    )).scalars().all()
    by_recipient: dict[str, list[Application]] = {}
    for app in apps:
        for email in (app.notification_emails or []):
            key = (email or "").strip().lower()
            if key:
                by_recipient.setdefault(key, []).append(app)
    if not by_recipient:
        return 0

    prefs_map = await resolve_recipient_prefs(db, list(by_recipient.keys()))
    sent = 0
    for email, recipient_apps in by_recipient.items():
        prefs = prefs_map.get(email, dict(APPSEC_PREF_DEFAULTS))
        if not prefs.get("weekly_enabled", True):
            continue
        if int(prefs.get("weekly_day", 0)) != today.weekday():
            continue
        already = (await db.execute(
            select(DigestRun.id).where(DigestRun.recipient == email,
                                       DigestRun.kind == "weekly",
                                       DigestRun.period_key == week)
        )).scalar_one_or_none()
        if already:
            continue
        try:
            await send_weekly_for_recipient(db, email, recipient_apps, prefs, week_key=week)
            sent += 1
        except Exception:  # pragma: no cover — one recipient must not block the rest
            logger.exception("weekly recap crashed for %s", email)
            await db.rollback()
    return sent


async def _loop() -> None:
    await asyncio.sleep(_INITIAL_DELAY)
    while True:
        try:
            async with async_session() as db:
                await tick_weekly(db)
        except Exception:  # pragma: no cover — must not kill the loop
            logger.exception("weekly recap pass crashed")
        await asyncio.sleep(_TICK_SECONDS)


def start_findings_notify_scheduler() -> None:
    global _task
    if _task is None:
        _task = asyncio.create_task(_loop())
