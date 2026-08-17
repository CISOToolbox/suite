"""Daily renewal-alert scheduler for the Asset module.

In-process asyncio loop (same pattern as Surface/Watch): ticks every
ASSET_RENEWAL_TICK_SECONDS but only acts once per ASSET_RENEWAL_INTERVAL_HOURS,
gated by the ``renewal.last_run`` row in app_settings so the cadence survives
restarts. On each run it scans every asset for deadlines falling within their
notice window — software licence renewals (licence.date_renouvellement, lead =
licence.preavis_jours) plus hardware fin_support / fin_vie (lead 90 d) — and
emails a single digest of everything due/overdue.

Mirrors the frontend deadline logic in Asset_app.js (_echeances): keep the two
in sync when the model changes.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import date, datetime, timezone
from html import escape as h_esc

from sqlalchemy import select

from src.database import async_session
from src.mailer import send_smtp
from src.models import AppSettings, Asset, Measure, Project, User
from src.routes.measures import max_measure_num, measure_id

logger = logging.getLogger("asset-renewal")

TICK_SECONDS = int(os.getenv("ASSET_RENEWAL_TICK_SECONDS", "3600"))
INTERVAL_HOURS = int(os.getenv("ASSET_RENEWAL_INTERVAL_HOURS", "24"))

_KIND_LABEL = {
    "licence": "Licence logiciel",
    "support": "Support matériel",
    "vie": "Fin de vie",
}


def _lead(raw, default: int) -> int:
    try:
        v = int(raw)
        return v if v >= 0 else default
    except (TypeError, ValueError):
        return default


def _parse(d) -> date | None:
    if not d:
        return None
    try:
        return date.fromisoformat(str(d)[:10])
    except (TypeError, ValueError):
        return None


def compute_due_echeances(assets, today: date) -> list[dict]:
    """Deadlines that are overdue or within their notice window.

    Pure function (no DB) so it can be unit-tested. Returns dicts with
    asset_id, asset_nom, kind, date (iso str), days (signed, <0 = overdue),
    sorted soonest first.
    """
    out: list[dict] = []

    def add(a, kind, raw_date, lead):
        d = _parse(raw_date)
        if d is None:
            return
        days = (d - today).days
        if days > lead:  # still outside the notice window
            return
        out.append({
            "project_id": a.project_id, "asset_id": a.id, "asset_nom": a.nom or a.id,
            "kind": kind, "date": d.isoformat(), "days": days,
        })

    for a in assets:
        lic = a.licence or {}
        add(a, "licence", lic.get("date_renouvellement"), _lead(lic.get("preavis_jours"), 30))
        add(a, "support", a.fin_support, 90)
        add(a, "vie", a.fin_vie, 90)

    out.sort(key=lambda e: e["days"])
    return out


def _days_label(days: int) -> str:
    if days == 0:
        return "aujourd'hui"
    if days < 0:
        return f"en retard de {-days} j"
    return f"dans {days} j"


def build_digest_html(due: list[dict], today: date) -> str:
    rows = ""
    for e in due:
        color = "#dc2626" if e["days"] < 0 else ("#f97316" if e["days"] <= 30 else "#eab308")
        rows += (
            "<tr>"
            f"<td style='padding:6px 10px'>{h_esc(_KIND_LABEL.get(e['kind'], e['kind']))}</td>"
            f"<td style='padding:6px 10px;font-weight:600'>{h_esc(e['asset_nom'])}</td>"
            f"<td style='padding:6px 10px'>{h_esc(e['date'])}</td>"
            f"<td style='padding:6px 10px;color:{color};font-weight:600'>{h_esc(_days_label(e['days']))}</td>"
            "</tr>"
        )
    return (
        "<div style='font-family:Arial,sans-serif;color:#1e293b'>"
        f"<h2 style='color:#0f172a'>Échéances à renouveler — {len(due)}</h2>"
        f"<p style='color:#64748b'>Au {today.isoformat()}, les actifs suivants ont une "
        "licence logiciel, un support matériel ou une fin de vie qui arrive à échéance "
        "(ou est dépassée).</p>"
        "<table style='border-collapse:collapse;font-size:14px'>"
        "<thead><tr style='background:#f1f5f9;text-align:left'>"
        "<th style='padding:6px 10px'>Type</th><th style='padding:6px 10px'>Actif</th>"
        "<th style='padding:6px 10px'>Date</th><th style='padding:6px 10px'>Échéance</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
        "<p style='color:#94a3b8;font-size:12px;margin-top:16px'>CISO Toolbox · Asset</p>"
        "</div>"
    )


async def _collect_recipients(db, due: list[dict], assets) -> list[str]:
    recips: set[str] = set()
    for r in os.getenv("ASSET_RENEWAL_RECIPIENTS", "").split(","):
        r = r.strip()
        if r:
            recips.add(r)
    due_ids = {e["asset_id"] for e in due}
    for a in assets:
        if a.id in due_ids:
            c = (a.licence or {}).get("contact")
            if c and str(c).strip():
                recips.add(str(c).strip())
    owner_ids = (await db.execute(
        select(Project.owner_id).where(Project.owner_id.isnot(None))
    )).scalars().all()
    if owner_ids:
        emails = (await db.execute(
            select(User.email).where(User.id.in_(owner_ids))
        )).scalars().all()
        for e in emails:
            if e:
                recips.add(e)
    return sorted(recips)


async def _ensure_measures(db, due: list[dict], assets) -> int:
    """Materialise one measure per due echeance, idempotently (FEAT-22).

    Dedup key auto_key = "<asset_id>:<kind>:<date>" with a unique index on
    (project_id, auto_key), so re-running the daily tick never duplicates a
    measure. Independent of the email digest. Does not commit — the caller
    owns the transaction.
    """
    if not due:
        return 0
    # Already-generated keys, per project.
    existing: set = set()
    rows = await db.execute(
        select(Measure.project_id, Measure.auto_key).where(Measure.auto_key.isnot(None))
    )
    for pid, key in rows.all():
        existing.add((str(pid), key))
    # Asset lookup for proprietaire / licence.contact, keyed (project_id, id).
    by_key = {(str(a.project_id), a.id): a for a in assets}
    next_num: dict = {}  # running MES-NNN counter per project
    created = 0
    for e in due:
        pid = e["project_id"]
        pid_s = str(pid)
        auto_key = f"{e['asset_id']}:{e['kind']}:{e['date']}"
        if (pid_s, auto_key) in existing:
            continue
        a = by_key.get((pid_s, e["asset_id"]))
        responsable = ""
        if a is not None:
            responsable = (a.proprietaire or "").strip() \
                or str((a.licence or {}).get("contact") or "").strip()
        if pid not in next_num:
            next_num[pid] = await max_measure_num(db, pid)
        next_num[pid] += 1
        kind_label = _KIND_LABEL.get(e["kind"], e["kind"])
        nom = e["asset_nom"]
        titles = {
            "licence": f"Renouveler la licence : {nom}",
            "support": f"Anticiper la fin de support : {nom}",
            "vie": f"Anticiper la fin de vie : {nom}",
        }
        note = {
            "at": datetime.now(timezone.utc).isoformat(),
            "by": "système",
            "text": f"Mesure générée automatiquement depuis l'échéance « {kind_label} » du {e['date']}.",
        }
        db.add(Measure(
            project_id=pid,
            id=measure_id(next_num[pid]),
            sort_order=next_num[pid],
            title=titles.get(e["kind"], f"Échéance : {nom}"),
            description=f"Échéance {kind_label} de l'actif {nom} ({e['asset_id']}) au {e['date']}.",
            statut="a_faire",
            responsable=responsable,
            echeance=e["date"],
            progress_log=[note],
            origine="echeance",
            asset_id=e["asset_id"],
            auto_key=auto_key,
        ))
        existing.add((pid_s, auto_key))
        created += 1
    if created:
        # FEAT-33 — scheduler measures are server-initiated writes.
        from src.routes.internal import bump_server_rev
        for pid2 in set(str(e["project_id"]) for e in due):
            await bump_server_rev(db, pid2)
    return created


async def run_now(db) -> dict:
    """Run a renewal check immediately (no cadence gate). Returns a summary.

    Used by the scheduler tick and by POST /api/internal/renewal-run (tests).
    Does not commit — the caller owns the transaction.
    """
    today = datetime.now(timezone.utc).date()
    assets = (await db.execute(select(Asset))).scalars().all()
    due = compute_due_echeances(assets, today)
    # Materialise measures regardless of whether a digest goes out (recipients
    # may be unconfigured) — the action plan must always be populated.
    measures_created = await _ensure_measures(db, due, assets)
    if not due:
        return {"due_count": 0, "sent": False, "reason": "no_due", "measures_created": measures_created}
    recipients = await _collect_recipients(db, due, assets)
    if not recipients:
        return {"due_count": len(due), "sent": False, "reason": "no_recipients", "measures_created": measures_created}
    html = build_digest_html(due, today)
    subject = f"[CISO Toolbox] {len(due)} échéance(s) à renouveler"
    sent_to, errors = [], []
    for r in recipients:
        ok, err = await asyncio.to_thread(send_smtp, r, subject, html)
        if ok:
            sent_to.append(r)
        else:
            errors.append({"to": r, "error": err})
    return {
        "due_count": len(due), "sent": bool(sent_to),
        "recipients": sent_to, "errors": errors,
        "measures_created": measures_created,
    }


async def _get_setting(db, key: str) -> str | None:
    row = await db.get(AppSettings, key)
    return row.value if row else None


async def _set_setting(db, key: str, value: str) -> None:
    row = await db.get(AppSettings, key)
    if row is None:
        db.add(AppSettings(key=key, value=value))
    else:
        row.value = value


async def _maybe_run() -> None:
    async with async_session() as db:
        now = datetime.now(timezone.utc)
        last = await _get_setting(db, "renewal.last_run")
        if last:
            try:
                if (now - datetime.fromisoformat(last)).total_seconds() < INTERVAL_HOURS * 3600:
                    return
            except ValueError:
                pass
        result = await run_now(db)
        # Journal only when the scheduler actually CREATED measures — routine
        # no-op ticks stay silent (same signal/noise rule as measures.sync).
        if (result or {}).get("measures_created"):
            from src.audit import log_write
            await log_write(db, None, None, "measure.auto_renewal", actor="scheduler",
                            entity_type="measure", details=result)
        await _set_setting(db, "renewal.last_run", now.isoformat())
        await db.commit()
        logger.info("renewal check: %s", result)


async def run_scheduler() -> None:
    await asyncio.sleep(15)  # let the DB warm up
    logger.info("renewal scheduler started (tick=%ds, interval=%dh)", TICK_SECONDS, INTERVAL_HOURS)
    while True:
        try:
            await _maybe_run()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("renewal tick failed")
        await asyncio.sleep(TICK_SECONDS)
