"""FEAT-34 — weekly per-user deadline digest.

Selects overdue / upcoming measures from the consolidated cache
(``MeasureCache`` + ``MeasureGroup``), matches them to the recipient,
renders a bilingual HTML email and delivers it through Pilot's own SMTP
settings (decrypted via settings_crypto).

Send discipline follows the Watch digest pattern: every attempt writes a
``DigestRun`` row and the unique (user_id, iso_week) pair guarantees ONE
email per user per ISO week, whatever the scheduler tick rate. An empty
digest is journalised as ``skipped_empty`` and NOT sent.

Auth posture: the feature needs a real recipient identity, so the whole
scheduler is a no-op when auth is disabled (AUTH_MODE=none) — see the
`user is None` sentinel contract.
"""
from __future__ import annotations

import asyncio
import html as _html
import logging
import uuid
from datetime import date, datetime, timezone
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import async_session
from src.models import (
    DigestRun,
    MeasureCache,
    MeasureGroup,
    MeasureGroupMember,
    ModuleRegistry,
    NotificationPrefs,
    User,
)

logger = logging.getLogger("pilot-deadline-digest")

_TICK_SECONDS = 3600
_INITIAL_DELAY = 120
_SEND_HOUR_UTC = 8  # spec Q1: fixed hour in v1
_OPEN_STATUSES = ("planned", "in_progress", "backlog")

_task: asyncio.Task | None = None


# ── selection ────────────────────────────────────────────────────────────

def _norm(s: str | None) -> str:
    return " ".join((s or "").split()).casefold()


def matches_user(assignee: str | None, email: str, name: str | None) -> bool:
    """A measure concerns the user when its free-text assignee equals the
    user's email OR full directory name (case/whitespace-insensitive).
    Unresolvable strings ("CTO + QA") match nobody — the digest does not
    guess (FEAT-34 spec)."""
    a = _norm(assignee)
    if not a:
        return False
    return a == _norm(email) or (bool(_norm(name)) and a == _norm(name))


def classify_due(due: str | None, today: date, upcoming_days: int) -> tuple[str, int] | None:
    """('overdue', days_late) | ('upcoming', days_left) | None (out of window
    or unparseable). due_date is an ISO string in the cache contract."""
    try:
        d = date.fromisoformat((due or "")[:10])
    except ValueError:
        return None
    delta = (d - today).days
    if delta < 0:
        return ("overdue", -delta)
    if delta <= upcoming_days:
        return ("upcoming", delta)
    return None


async def collect_items(db: AsyncSession, prefs: NotificationPrefs,
                        user: User, today: date | None = None) -> list[dict]:
    """Overdue/upcoming measures for one recipient, deduplicating grouped
    measures behind their META-NNN group (spec: members never appear)."""
    today = today or date.today()
    wanted_modules = set(prefs.modules or [])

    grouped_ids = set((await db.execute(select(MeasureGroupMember.measure_id))).scalars().all())

    items: list[dict] = []
    rows = (await db.execute(
        select(MeasureCache).where(MeasureCache.data["status"].astext.in_(_OPEN_STATUSES))
    )).scalars().all()
    for mc in rows:
        if mc.id in grouped_ids:
            continue
        if wanted_modules and mc.module not in wanted_modules:
            continue
        d = mc.data or {}
        cls = classify_due(d.get("due_date"), today, prefs.upcoming_days)
        if cls is None:
            continue
        if prefs.scope != "all" and not matches_user(d.get("assignee"), user.email, user.name):
            continue
        items.append({
            "kind": cls[0], "days": cls[1], "due": (d.get("due_date") or "")[:10],
            "ref": mc.source_id, "title": d.get("title") or d.get("mesure") or "",
            "modules": [mc.module], "module": mc.module,
            "entity_id": mc.entity_id or "", "source_id": mc.source_id,
            "group_id": "",
        })

    groups = (await db.execute(
        select(MeasureGroup).where(MeasureGroup.status.in_(_OPEN_STATUSES))
    )).scalars().all()
    for g in groups:
        cls = classify_due(g.due_date, today, prefs.upcoming_days)
        if cls is None:
            continue
        if prefs.scope != "all" and not matches_user(g.responsible, user.email, user.name):
            continue
        members = (await db.execute(
            select(MeasureCache)
            .join(MeasureGroupMember, MeasureGroupMember.measure_id == MeasureCache.id)
            .where(MeasureGroupMember.group_id == g.id)
        )).scalars().all()
        mods: list[str] = []
        for m in members:
            if m.module not in mods:
                mods.append(m.module)
        if wanted_modules and not (set(mods) & wanted_modules):
            continue
        items.append({
            "kind": cls[0], "days": cls[1], "due": (g.due_date or "")[:10],
            "ref": g.ref or "", "title": g.title or "",
            "modules": mods, "module": "pilot",
            "entity_id": "", "source_id": "", "group_id": str(g.id),
        })

    if not prefs.include_overdue:
        items = [i for i in items if i["kind"] != "overdue"]
    items.sort(key=lambda i: (i["kind"] != "overdue", i["due"]))
    return items


# ── rendering ────────────────────────────────────────────────────────────

_L = {
    "fr": {
        "subject": "{prefix} Vos échéances — {n} action(s) à suivre",
        "hello": "Bonjour {name},",
        "intro": "Voici votre point hebdomadaire sur les échéances du plan d'action sécurité.",
        "overdue": "Échéances dépassées ({n})",
        "upcoming": "À échéance sous {days} jours ({n})",
        "late": "{d} j de retard",
        "left_0": "aujourd'hui",
        "left": "dans {d} j",
        "open": "Ouvrir",
        "footer": "Vous recevez cet email selon vos préférences de notification dans Pilot (menu profil → Notifications).",
    },
    "en": {
        "subject": "{prefix} Your deadlines — {n} action(s) to follow up",
        "hello": "Hello {name},",
        "intro": "Here is your weekly summary of the security action plan deadlines.",
        "overdue": "Overdue ({n})",
        "upcoming": "Due within {days} days ({n})",
        "late": "{d} d late",
        "left_0": "today",
        "left": "in {d} d",
        "open": "Open",
        "footer": "You receive this email according to your notification preferences in Pilot (profile menu → Notifications).",
    },
}


_PUBLIC_BASE = ""


def _abs(url: str) -> str:
    """module_registry URLs are often proxy-relative ("/risk/"); an email
    needs absolute links. PUBLIC_BASE_URL (compose) provides the prefix —
    without it relative links are kept as-is (better than dropping them)."""
    import os
    base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    if url.startswith("/") and base:
        return base + url
    return url


def _item_url(item: dict, ext_urls: dict[str, str], pilot_url: str) -> str:
    """FEAT-13 deep link into the source module; groups open in Pilot."""
    if item["group_id"]:
        pilot_url = _abs(pilot_url)
        return (pilot_url.rstrip("/") + "/?group=" + item["group_id"] + "#measures") if pilot_url else ""
    base = _abs(ext_urls.get(item["module"], ""))
    if not base:
        return ""
    from urllib.parse import quote
    return (base.rstrip("/") + "/?entity=" + quote(item["entity_id"])
            + "&measure=" + quote(item["source_id"]) + "#measures")


def render_digest_html(items: list[dict], user_name: str, lang: str,
                       upcoming_days: int, ext_urls: dict[str, str],
                       pilot_url: str) -> str:
    """Self-contained inline-styled HTML. Titles/refs are user data → escaped."""
    L = _L.get(lang) or _L["fr"]
    e = _html.escape

    def _section(kind: str, color: str, label: str) -> str:
        rows = [i for i in items if i["kind"] == kind]
        if not rows:
            return ""
        h = ('<h2 style="color:#2c3e50;border-bottom:2px solid ' + color
             + ';padding-bottom:6px;margin-top:28px">' + e(label) + "</h2>")
        h += '<table style="border-collapse:collapse;width:100%;background:#fff">'
        for i in rows:
            when = (L["late"].format(d=i["days"]) if kind == "overdue"
                    else (L["left_0"] if i["days"] == 0 else L["left"].format(d=i["days"])))
            mods = " ".join('<span style="font-family:monospace;font-size:11px;background:#eef2f7;'
                            'border-radius:8px;padding:1px 7px">' + e(m) + "</span>" for m in i["modules"])
            url = _item_url(i, ext_urls, pilot_url)
            link = ('<a href="' + e(url) + '" style="color:#2563eb">' + e(L["open"]) + " ↗</a>") if url else ""
            h += ('<tr style="border-bottom:1px solid #e5e7eb">'
                  '<td style="padding:7px 10px;white-space:nowrap;font-family:monospace;font-size:12px;color:#6b7280">'
                  + e(i["ref"]) + "</td>"
                  '<td style="padding:7px 10px">' + e(i["title"]) + "</td>"
                  '<td style="padding:7px 10px">' + mods + "</td>"
                  '<td style="padding:7px 10px;white-space:nowrap">' + e(i["due"]) + "</td>"
                  '<td style="padding:7px 10px;white-space:nowrap;color:' + color + ';font-weight:600">'
                  + e(when) + "</td>"
                  '<td style="padding:7px 10px;white-space:nowrap">' + link + "</td></tr>")
        return h + "</table>"

    n_over = sum(1 for i in items if i["kind"] == "overdue")
    n_up = len(items) - n_over
    body = '<p>' + e(L["hello"].format(name=user_name or "")) + "</p>"
    body += "<p>" + e(L["intro"]) + "</p>"
    body += _section("overdue", "#c0392b", L["overdue"].format(n=n_over))
    body += _section("upcoming", "#e67e22", L["upcoming"].format(days=upcoming_days, n=n_up))
    body += ('<p style="margin-top:26px;font-size:12px;color:#7f8c8d">' + e(L["footer"]) + "</p>")
    return ('<!doctype html><html><body style="font-family:Arial,sans-serif;color:#222;'
            'line-height:1.5;background:#f5f5f5;margin:0;padding:0">'
            '<div style="max-width:760px;margin:0 auto;padding:24px">' + body + "</div></body></html>")


# ── delivery ─────────────────────────────────────────────────────────────

async def _smtp_config(db: AsyncSession) -> dict:
    from src.routes.settings import _get_setting
    cfg = {k: await _get_setting("smtp_" + k, db) for k in ("host", "port", "user", "password", "from", "tls")}
    return cfg


def _send_email(cfg: dict, recipient: str, subject: str, html: str) -> None:
    from src.mailer_common import smtp_deliver
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    sender = cfg.get("from") or cfg.get("user") or ""
    msg["From"] = formataddr(("CISO Toolbox", sender))
    msg["To"] = recipient
    msg.attach(MIMEText(html, "html", "utf-8"))
    smtp_deliver(
        cfg["host"], int(cfg.get("port") or 587),
        use_tls=str(cfg.get("tls") or "true").lower() in ("1", "true", "yes"),
        username=cfg.get("user") or "", password=cfg.get("password") or "",
        sender=sender, recipients=[recipient], raw_message=msg.as_string(),
    )


def iso_week_key(d: date) -> str:
    y, w, _ = d.isocalendar()
    return f"{y}-W{w:02d}"


async def send_digest_for_user(db: AsyncSession, user: User, prefs: NotificationPrefs,
                               *, week_key: str | None = None, force: bool = False) -> str:
    """Build + journal + send one digest. Returns the run status.

    ``force`` (the "send me a preview now" button) bypasses the weekly
    idempotence by using a unique week key, and sends even when empty so
    the user can validate their SMTP path.
    """
    week = week_key or iso_week_key(date.today())
    if force:
        week = "t-" + uuid.uuid4().hex[:8]

    items = await collect_items(db, prefs, user)
    ext_urls = {m.id: m.external_url or "" for m in
                (await db.execute(select(ModuleRegistry))).scalars().all()}
    pilot_url = ext_urls.get("pilot", "")

    if not items and not force:
        run = DigestRun(user_id=user.id, iso_week=week, status="skipped_empty")
        db.add(run)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
        return "skipped_empty"

    lang = prefs.lang if prefs.lang in ("fr", "en") else "fr"
    html = render_digest_html(items, user.name or user.email, lang,
                              prefs.upcoming_days, ext_urls, pilot_url)
    prefix = (getattr(prefs, "subject_prefix", "") or "[CISO Toolbox]").strip()
    subject = _L[lang]["subject"].format(prefix=prefix, n=len(items))

    cfg = await _smtp_config(db)
    status, err = "sent", ""
    if not cfg.get("host"):
        status, err = "failed", "SMTP not configured in Pilot settings"
    else:
        try:
            await asyncio.to_thread(_send_email, cfg, user.email, subject, html)
        except Exception as exc:
            status, err = "failed", str(exc)[:2000]

    db.add(DigestRun(user_id=user.id, iso_week=week, status=status,
                     items_count=len(items), error_message=err, body_html=html))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return "duplicate"
    logger.info("deadline digest %s for %s (%s items)", status, user.email, len(items))
    return status


# ── scheduler ────────────────────────────────────────────────────────────

async def tick_digests(db: AsyncSession, now: datetime | None = None) -> int:
    """One scheduler pass: send to every enabled user whose day is today
    and who was not served this ISO week. Returns the number of attempts."""
    now = now or datetime.now(timezone.utc)
    if now.hour < _SEND_HOUR_UTC:
        return 0
    today = now.date()
    week = iso_week_key(today)
    sent = 0
    pairs = (await db.execute(
        select(User, NotificationPrefs)
        .join(NotificationPrefs, NotificationPrefs.user_id == User.id)
        .where(NotificationPrefs.enabled.is_(True))
    )).all()
    for user, prefs in pairs:
        if prefs.day_of_week != today.weekday():
            continue
        already = (await db.execute(
            select(DigestRun.id).where(DigestRun.user_id == user.id,
                                       DigestRun.iso_week == week)
        )).scalar_one_or_none()
        if already:
            continue
        try:
            await send_digest_for_user(db, user, prefs, week_key=week)
            sent += 1
        except Exception:  # pragma: no cover — one user must not block the rest
            logger.exception("deadline digest crashed for %s", user.email)
            await db.rollback()
    return sent


async def _loop() -> None:
    await asyncio.sleep(_INITIAL_DELAY)
    while True:
        try:
            from src.auth import auth_enabled
            if auth_enabled():  # AUTH_MODE=none → no identities → no-op (§4.4)
                async with async_session() as db:
                    await tick_digests(db)
        except Exception:  # pragma: no cover — must not kill the loop
            logger.exception("deadline digest pass crashed")
        await asyncio.sleep(_TICK_SECONDS)


def start_deadline_digest_scheduler() -> None:
    global _task
    if _task is None:
        _task = asyncio.create_task(_loop())
