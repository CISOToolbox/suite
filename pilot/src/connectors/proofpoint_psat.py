"""Proofpoint Security Awareness Training (PSAT) connector for Pilot.

Pulls training-campaign completion from the PSAT **Results API** and:

  (1) feeds the per-user **"sensibilisation" compliance proof** in Access —
      only for users whose email is on a configured domain AND who completed
      the configured *mandatory* campaign(s);
  (2) [Lot 2] produces tenant-wide reporting (completion %, overdue) per
      tracked campaign for the Pilot dashboard;
  (3) [Lot 3] raises overdue-cohort measures into the action plan.

API (confirmed from the official SDKs — regg00/psat-result-api,
pfptcommunity/psat-api-python):
  * auth header:  ``x-apikey-token: <token>``
  * base URL:     ``https://results.{region}.securityeducation.com/api/reporting/v0.3.0``
  * endpoints:    ``/training`` (+ ``/phishing``, ``/cyberstrength`` …)
  * pagination:   ``page[size]`` (<=1000) / ``page[number]``
  * filters:      ``filter[_useremailaddress]`` …  (JSON:API response shape)

Credentials live in ``AppSettings`` under ``connector_proofpoint_psat_<field>``
(framework convention). Fields: ``region``, ``api_key`` (secret, optional),
``email_domains``, ``tracked_campaigns``, ``mandatory_campaigns``,
``lookback_days``.

**Hybrid / demo mode** — when no ``api_key`` is configured (and demo mode is
not disabled), ``run`` synthesizes deterministic completion data over the
**Access referential** so the integration is demoable offline (no live
Proofpoint tenant). Mirrors the AWS connector's hybrid behaviour.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import SERVICE_TOKEN
from src.models import AppSettings, KpiDefinition, KpiFrameworkMapping, MeasureCache, ModuleRegistry
from src.settings_crypto import decrypt_setting, is_secret_key

logger = logging.getLogger("pilot.connectors.proofpoint_psat")

CONNECTOR_ID = "proofpoint_psat"
_API_VERSION = "0.3.0"
_PAGE_SIZE = 1000
_MAX_PAGES = 50
_HTTP_TIMEOUT = 20.0
# The PSAT Results API is aggressively rate-limited (429 on rapid pagination).
# Honour Retry-After with a bounded exponential backoff, and stay polite
# between pages so a normal multi-page run does not trip the limiter.
_MAX_RETRIES_429 = 4
_RETRY_BASE_WAIT = 3.0   # seconds, doubled each attempt
_RETRY_MAX_WAIT = 30.0   # cap a single wait (never block the run for minutes)
_INTERPAGE_DELAY = 0.6   # small pause between successive pages


# ---------- Configuration ------------------------------------------------- #

DETAIL_KEY = "psat_awareness_detail"  # AppSettings key holding the panel JSON


async def _get_setting(key: str, db: AsyncSession) -> str:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    raw = (s.value if s else "") or ""
    # Credentials are stored encrypted; pre-migration rows have no marker and
    # come back unchanged (see settings_crypto).
    return decrypt_setting(raw) if is_secret_key(key) else raw


async def _set_setting(key: str, value: str, db: AsyncSession) -> None:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    if s:
        s.value = value
    else:
        db.add(AppSettings(key=key, value=value))


async def get_config(db: AsyncSession) -> dict[str, Any]:
    """Read connector config from AppSettings (connector_proofpoint_psat_*)."""
    async def field(name: str) -> str:
        import os
        return (await _get_setting(f"connector_{CONNECTOR_ID}_{name}", db)) or os.getenv(
            f"CONNECTOR_{CONNECTOR_ID.upper()}_{name.upper()}", ""
        )

    region = (await field("region") or "eu").strip().lower()
    if region not in ("us", "eu", "ap"):
        region = "eu"
    return {
        "region": region,
        "api_key": (await field("api_key")).strip(),
        "email_domains": _split(await field("email_domains"), ","),
        "tracked_campaigns": _split(await field("tracked_campaigns"), ";"),
        "mandatory_campaigns": _split(await field("mandatory_campaigns"), ";"),
        "campaign_filter": (await field("campaign_filter")).strip(),
        "retention_months": _to_int(await field("retention_months"), _DEFAULT_RETENTION_MONTHS),
        "lookback_days": _to_int(await field("lookback_days"), 365),
    }


def _split(raw: str, sep: str) -> list[str]:
    return [p.strip() for p in (raw or "").replace("\n", sep).split(sep) if p.strip()]


def _to_int(raw: str, default: int) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


async def _demo_enabled(db: AsyncSession) -> bool:
    """Demo mode is on unless explicitly disabled (demo_mode='false')."""
    return (await _get_setting("demo_mode", db)) != "false"


# ---------- PSAT REST client ---------------------------------------------- #

def _base_url(region: str) -> str:
    return f"https://results.{region}.securityeducation.com/api/reporting/v{_API_VERSION}"


def _headers(api_key: str) -> dict[str, str]:
    return {"x-apikey-token": api_key, "Accept": "application/json"}


def _retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    """Parse a ``Retry-After`` header expressed in seconds. HTTP-date form is
    ignored (returns None) — the caller falls back to exponential backoff."""
    raw = resp.headers.get("Retry-After", "").strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


async def _get_page(client: httpx.AsyncClient, url: str, params: dict) -> httpx.Response:
    """GET one page, transparently retrying on HTTP 429. Honours ``Retry-After``
    when present (capped), otherwise backs off exponentially. Returns the last
    response (still 429) once retries are exhausted so the caller can
    ``raise_for_status`` and surface a clean error."""
    resp = await client.get(url, params=params)
    for attempt in range(_MAX_RETRIES_429):
        if resp.status_code != 429:
            return resp
        wait = _retry_after_seconds(resp)
        if wait is None:
            wait = _RETRY_BASE_WAIT * (2 ** attempt)
        wait = min(wait, _RETRY_MAX_WAIT)
        logger.warning(
            "PSAT 429 (rate-limited) — retry %d/%d in %.1fs", attempt + 1, _MAX_RETRIES_429, wait
        )
        await asyncio.sleep(wait)
        resp = await client.get(url, params=params)
    return resp


async def _fetch_all(endpoint: str, cfg: dict, params: Optional[dict] = None) -> list[dict]:
    """Fetch every page of a JSON:API list endpoint. Returns the flattened
    ``data[]`` records (each ``{type, id, attributes:{...}}``). Rate-limit
    aware — see ``_get_page``."""
    url = _base_url(cfg["region"]) + endpoint
    out: list[dict] = []
    base_params = dict(params or {})
    base_params["page[size]"] = _PAGE_SIZE
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_headers(cfg["api_key"])) as client:
        for page in range(1, _MAX_PAGES + 1):
            p = dict(base_params)
            p["page[number]"] = page
            if page > 1:
                await asyncio.sleep(_INTERPAGE_DELAY)  # stay polite between pages
            resp = await _get_page(client, url, p)
            resp.raise_for_status()
            body = resp.json()
            data = body.get("data", []) if isinstance(body, dict) else []
            out.extend(data)
            if len(data) < _PAGE_SIZE:
                break
    return out


def _attr(attrs: dict, *names: str) -> Any:
    """Case-insensitive attribute lookup with several candidate names —
    PSAT attribute spelling varies by tenant/version."""
    low = {str(k).lower().replace("_", ""): v for k, v in (attrs or {}).items()}
    for n in names:
        key = n.lower().replace("_", "")
        if key in low and low[key] not in (None, ""):
            return low[key]
    return None


def _is_completed(status: Any) -> bool:
    """True when a PSAT user-assignment status denotes completion.

    The Results API ``userassignmentstatus`` uses compound values such as
    ``"Overdue - Completed"`` (completed **late**) alongside ``"Completed"``.
    Match on substring so late completions still count, while ``"Not Started"``
    / ``"Overdue - Not Started"`` / ``"In Progress"`` / ``"Past Due"`` do not."""
    s = str(status or "").strip().lower()
    return ("complet" in s) or ("passed" in s) or ("termin" in s)


def _norm(s: str) -> str:
    return str(s or "").strip().lower()


def _campaign_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")[:60]


def _user_excluded(attrs: dict) -> bool:
    """True when a user must NOT count toward completion stats: an inactive
    account (``useractiveflag`` false), a user removed from the assignment
    (``userremovedfromassignment`` true), or a deleted account
    (``userdeleteddate`` set). Avoids inflating "not completed" with people
    who have left — matching what the PSAT console shows."""
    active = _attr(attrs, "useractiveflag")
    if active is not None and _norm(active) in ("false", "0", "no"):
        return True
    if _norm(_attr(attrs, "userremovedfromassignment")) in ("true", "1", "yes"):
        return True
    if _date_only(_attr(attrs, "userdeleteddate", "userdeletedate")):
        return True
    return False


# ---------- Per-user completion model ------------------------------------- #
#
# Shape produced by both the real fetch and the demo synth:
#   { email_lower: { "email": str,
#                    "campaigns": { campaign_name: {"completed": bool,
#                                                   "date": "YYYY-MM-DD"} } } }

def _parse_training(records: list[dict], tracked: list[str]) -> dict[str, dict]:
    tracked_norm = {_norm(c) for c in tracked}
    users: dict[str, dict] = {}
    skipped_no_email = 0
    for rec in records:
        attrs = rec.get("attributes", rec) if isinstance(rec, dict) else {}
        email = _attr(attrs, "useremailaddress", "emailaddress", "email")
        campaign = _attr(attrs, "assignmentname", "campaignname", "trainingname", "nameofassignment")
        if not email or not campaign:
            skipped_no_email += 1
            continue
        if tracked_norm and _norm(campaign) not in tracked_norm:
            continue
        if _user_excluded(attrs):
            continue  # inactive / removed / deleted user — not counted
        # `userassignmentstatus` is the authoritative per-user completion state
        # ("Completed", "Overdue - Completed", "Not Started"…). `assignmentstatus`
        # is a schedule-level flag that stays "Not Started" and must NOT be used.
        status = _attr(attrs, "userassignmentstatus", "assignmentstatus", "userstatus", "status")
        date = _attr(attrs, "forcecompleteddate", "moduleattemptdate", "modulelastaction",
                     "completiondate", "datecompleted", "completedtimestamp")
        udue = _date_only(_attr(attrs, "assignmentduedate", "duedate"))
        em = _norm(email)
        u = users.setdefault(em, {"email": email, "campaigns": {}})
        # A curriculum spans several module rows per user — keep it completed once
        # any row says so, and don't lose a completion/due date already captured.
        prev = u["campaigns"].get(campaign)
        completed = _is_completed(status) or bool(prev and prev.get("completed"))
        # Keep the LATEST completion timestamp seen for this (user, campaign);
        # lateness is decided per-user against the user's OWN due date in
        # _build_reporting, NOT from the "Overdue" string (which only means the
        # assignment is now past due), NOR the campaign-wide max due (deadlines
        # are per-user when enrollment is staggered).
        new_date = _date_only(date)
        prev_date = prev.get("date") if prev else ""
        cdate = max(new_date, prev_date) if (new_date or prev_date) else ""
        prev_due = prev.get("due") if prev else ""
        cdue = max(udue, prev_due) if (udue or prev_due) else ""
        u["campaigns"][campaign] = {"completed": completed, "date": cdate, "due": cdue}
    if skipped_no_email:
        logger.info("PSAT: %d training records skipped (missing email/campaign)", skipped_no_email)
    return users


def _date_only(val: Any) -> str:
    s = str(val or "")
    return s[:10] if len(s) >= 10 else s


# ---------- Campaign discovery + due-date severity ------------------------ #

_GRACE_DAYS = 30  # fixed grace window after the initial due date (PSAT has no grace field)
_RED_MARGIN_DAYS = 15  # go red this many days before the grace period ends
_DEFAULT_RETENTION_MONTHS = 12  # keep past-due trainings as KPIs for this many months


def _campaign_meta(records: list[dict]) -> dict[str, dict]:
    """Aggregate per-campaign (``assignmentname``) schedule metadata: latest due
    date, earliest start date, and whether any non-deleted row exists."""
    meta: dict[str, dict] = {}
    for rec in records:
        attrs = rec.get("attributes", rec) if isinstance(rec, dict) else {}
        name = _attr(attrs, "assignmentname", "campaignname", "trainingname", "nameofassignment")
        if not name:
            continue
        due = _date_only(_attr(attrs, "assignmentduedate", "duedate"))
        start = _date_only(_attr(attrs, "assignmentstartdate", "startdate"))
        deleted = _norm(_attr(attrs, "assignmentdeleted")) in ("true", "1", "yes")
        m = meta.setdefault(name, {"due": "", "start": "", "active": False})
        if due and due > m["due"]:
            m["due"] = due
        if start and (not m["start"] or start < m["start"]):
            m["start"] = start
        if not deleted:
            m["active"] = True
    return meta


def _months_ago(today: str, months: int) -> str:
    """ISO date ``months`` calendar months before ``today`` (day clamped to the
    target month's length)."""
    d = date.fromisoformat(today)
    total = d.year * 12 + (d.month - 1) - months
    y, m = divmod(total, 12)
    m += 1
    first_next = date(y + 1, 1, 1) if m == 12 else date(y, m + 1, 1)
    last_day = (first_next - timedelta(days=1)).day
    return date(y, m, min(d.day, last_day)).isoformat()


def _discover_campaigns(meta: dict[str, dict], substr: str, today: str,
                        retention_months: int = _DEFAULT_RETENTION_MONTHS) -> list[str]:
    """Campaign names containing ``substr`` (case-insensitive) worth showing as a
    KPI: already started (start <= today), not archived (at least one non-deleted
    row), and — if the due date has passed — ended within ``retention_months``.

    A recently-past due date does NOT exclude a training: in PSAT users keep
    completing after the deadline ("Overdue - Completed"), and a past-due
    training with missing users is exactly what must surface (red). Only
    trainings whose deadline is older than the retention window drop off.
    The due date drives severity; missing start/due dates are permissive."""
    needle = _norm(substr)
    cutoff = _months_ago(today, retention_months) if retention_months > 0 else ""
    out: list[str] = []
    for name, m in meta.items():
        if needle and needle not in _norm(name):
            continue
        if not m.get("active"):
            continue  # all rows deleted → archived
        if m.get("start") and m["start"] > today:
            continue  # scheduled in the future — not started yet
        if cutoff and m.get("due") and m["due"] < cutoff:
            continue  # ended beyond the retention window
        out.append(name)
    return sorted(out)


def _grace_end(due: str) -> str:
    """Grace-period end = initial due date + a fixed grace window (PSAT exposes
    no grace date). ISO date, or '' when ``due`` is missing/invalid."""
    if not due:
        return ""
    try:
        return (date.fromisoformat(due) + timedelta(days=_GRACE_DAYS)).isoformat()
    except ValueError:
        return ""


def _severity(pct: float, due: str, today: str) -> str:
    """green / amber / red for a completion KPI. PSAT exposes only the initial
    due date, so a fixed grace window (``_GRACE_DAYS``) is added after it:
      green : 100% complete, OR the initial deadline (``due``) is not yet passed
      amber : initial deadline passed, still more than _RED_MARGIN_DAYS before
              the grace end
      red   : within _RED_MARGIN_DAYS of the grace end (due + _GRACE_DAYS), or past."""
    if pct >= 100.0 or not due:
        return "green"
    try:
        due_d = date.fromisoformat(due)
        today_d = date.fromisoformat(today)
    except ValueError:
        return "green"
    red_from = due_d + timedelta(days=_GRACE_DAYS - _RED_MARGIN_DAYS)
    if today_d >= red_from:
        return "red"
    if today_d >= due_d:
        return "amber"
    return "green"


# ---------- Demo synthesis (offline, over the Access referential) --------- #

async def _demo_users(cfg: dict, campaigns: list[str], db: AsyncSession) -> dict[str, dict]:
    """Build deterministic completion data from the Access referential so the
    connector is demoable without a live PSAT tenant. ~70% of users 'complete'
    each tracked campaign (stable per email+campaign)."""
    emails = [u["email"] for u in await _fetch_access_referential(db) if u.get("email")]
    today = datetime.now(timezone.utc).date()
    users: dict[str, dict] = {}
    for email in emails:
        camps: dict[str, dict] = {}
        for campaign in campaigns:
            h = int(hashlib.sha256(f"{_norm(email)}|{_norm(campaign)}".encode()).hexdigest(), 16)
            completed = (h % 10) < 7
            day = today - timedelta(days=(h % 120))
            camps[campaign] = {"completed": completed, "date": day.isoformat() if completed else ""}
        users[_norm(email)] = {"email": email, "campaigns": camps}
    logger.info("PSAT demo: synthesized completion for %d Access users", len(users))
    return users


# ---------- Access bridge -------------------------------------------------- #

async def _access_base(db: AsyncSession) -> Optional[str]:
    r = await db.execute(select(ModuleRegistry).where(ModuleRegistry.id == "access"))
    m = r.scalar_one_or_none()
    if not m or not m.internal_url:
        return None
    return m.internal_url.rstrip("/")


async def _fetch_access_referential(db: AsyncSession) -> list[dict]:
    base = await _access_base(db)
    if not base or not SERVICE_TOKEN:
        return []
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(base + "/api/internal/referential",
                                    headers={"X-Service-Token": SERVICE_TOKEN})
            if resp.is_success and isinstance(resp.json(), list):
                return resp.json()
    except Exception as e:  # noqa: BLE001 — best effort
        logger.warning("PSAT: failed to read Access referential: %s", e)
    return []


def _build_access_payload(users: dict[str, dict], cfg: dict, today: str) -> list[dict]:
    """Awareness-sync payload: every user on a configured domain, with the full
    per-training snapshot (ALL their tracked campaigns, not just completed ones
    — Access needs the in-progress/overdue ones to drive compliance and build
    the cumulative history). ``overdue`` = not completed AND past the user's own
    due date. Access owns the history merge + compliance state machine."""
    domains = {d.lower().lstrip("@") for d in cfg["email_domains"]}
    out: list[dict] = []
    for u in users.values():
        email = u["email"]
        dom = email.split("@")[-1].lower() if "@" in email else ""
        if domains and dom not in domains:
            continue
        trainings: list[dict] = []
        for name, c in u["campaigns"].items():
            completed = bool(c.get("completed"))
            due = c.get("due", "") or ""
            trainings.append({
                "campaign": name,
                "completed": completed,
                "due_date": due,
                "completion_date": c.get("date", "") or "",
                "overdue": (not completed) and bool(due) and due < today,
            })
        if not trainings:
            continue
        out.append({"email": email, "trainings": trainings})
    return out


async def _push_access(db: AsyncSession, payload: list[dict]) -> dict:
    base = await _access_base(db)
    if not base or not SERVICE_TOKEN:
        return {"pushed": 0, "error": "access module or service token unavailable"}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(
                base + "/api/internal/awareness-sync",
                headers={"X-Service-Token": SERVICE_TOKEN},
                json={"users": payload},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:  # noqa: BLE001
        logger.warning("PSAT: awareness-sync push failed: %s", e)
        return {"pushed": 0, "error": str(e)}


# ---------- Reporting (Lot 2: tenant-wide, per campaign) ------------------ #

def _build_reporting(users: dict[str, dict], tracked: list[str], mandatory: list[str],
                     today: str) -> dict:
    """Aggregate completion per tracked campaign over ALL seen users (tenant —
    no domain filter), plus the overall mandatory-completion rate and the top
    overdue users. Due dates and lateness/severity are computed PER USER (each
    user's own ``assignmentduedate``); ``today`` is the ISO reference date."""
    campaigns = []
    for camp in tracked:
        cn = _norm(camp)
        assigned = completed = completed_late = 0
        overdue_users: list[str] = []
        late_users: list[str] = []
        min_inc_due = ""  # earliest due among INCOMPLETE users → most urgent, drives severity
        for u in users.values():
            c = {_norm(k): v for k, v in u["campaigns"].items()}.get(cn)
            if c is None:
                continue
            assigned += 1
            udue = c.get("due", "")
            if c.get("completed"):
                completed += 1
                # Late ONLY if completion happened after the user's OWN due date.
                cdate = c.get("date", "")
                if udue and cdate and cdate > udue:
                    completed_late += 1
                    late_users.append(u["email"])
            else:
                overdue_users.append(u["email"])
                if udue and (not min_inc_due or udue < min_inc_due):
                    min_inc_due = udue
        overdue_users.sort()
        late_users.sort()
        pct = round(100.0 * completed / assigned, 1) if assigned else 0.0
        campaigns.append({
            "name": camp, "slug": _campaign_slug(camp),
            "assigned": assigned, "completed": completed,
            "completed_late": completed_late,
            "overdue": assigned - completed,
            "pct": pct,
            "due_date": min_inc_due,
            "grace_date": _grace_end(min_inc_due),
            "severity": _severity(pct, min_inc_due, today),
            "overdue_users": overdue_users[:100],
            "late_users": late_users[:100],
        })

    total = len(users)
    compliant = 0
    completed_late_total = 0
    overdue: list[dict] = []
    for u in users.values():
        camps = {_norm(k): v for k, v in u["campaigns"].items()}
        missing = [m for m in mandatory
                   if not (camps.get(_norm(m)) and camps[_norm(m)].get("completed"))]
        if missing:
            overdue.append({"email": u["email"], "missing": missing})
        else:
            compliant += 1
            # Late overall if any mandatory campaign was completed after the
            # user's own due date.
            late_any = False
            for m in mandatory:
                cm = camps.get(_norm(m))
                if cm and cm.get("due") and cm.get("date") and cm["date"] > cm["due"]:
                    late_any = True
                    break
            if late_any:
                completed_late_total += 1
    overdue.sort(key=lambda x: x["email"])
    return {
        "overall_completion_pct": round(100.0 * compliant / total, 1) if total else 0.0,
        "users_total": total,
        "users_compliant": compliant,
        "completed_late_total": completed_late_total,
        "campaigns": campaigns,
        "overdue": overdue[:25],
        "overdue_total": len(overdue),
    }


async def _store_detail(reporting: dict, db: AsyncSession) -> dict:
    """Persist the latest panel payload + append a daily trend point (capped)."""
    prev_raw = await _get_setting(DETAIL_KEY, db)
    try:
        prev = json.loads(prev_raw) if prev_raw else {}
    except (ValueError, TypeError):
        prev = {}
    today = datetime.now(timezone.utc).date().isoformat()
    trend = [t for t in prev.get("trend", []) if isinstance(t, dict) and t.get("date") != today]
    trend.append({"date": today, "pct": reporting["overall_completion_pct"]})
    out = dict(reporting)
    out["trend"] = trend[-60:]
    out["generated_at"] = datetime.now(timezone.utc).isoformat()
    await _set_setting(DETAIL_KEY, json.dumps(out, ensure_ascii=False), db)
    await db.commit()
    return out


# ---------- Action plan (Lot 3: overdue-cohort measures) ------------------ #

_MEASURE_PREFIX = "psat-overdue-"


async def _sync_measures(reporting: dict, db: AsyncSession) -> int:
    """Raise one MeasureCache row per tracked campaign with overdue users
    (idempotent on a stable source_id). Cohorts that no longer have overdue
    users are marked 'termine' so they leave the active action plan."""
    now = datetime.now(timezone.utc)
    due = (now.date() + timedelta(days=30)).isoformat()
    active: dict[str, dict] = {}
    for c in reporting.get("campaigns", []):
        # Only raise an action-plan measure once the deadline has passed with
        # users still missing (severity red) — not while there is still time.
        if (c.get("overdue") or 0) > 0 and c.get("severity") == "red":
            slug = c.get("slug") or _campaign_slug(c["name"])
            active[_MEASURE_PREFIX + slug] = c

    rows = (await db.execute(
        select(MeasureCache).where(
            MeasureCache.module == "pilot",
            MeasureCache.source_id.like(_MEASURE_PREFIX + "%"),
        )
    )).scalars().all()
    existing = {r.source_id: r for r in rows}

    for sid, c in active.items():
        data = {
            "title": f"Sensibilisation : {c['overdue']} utilisateur(s) en retard — {c['name']}",
            "description": f"{c['completed']}/{c['assigned']} ont complété « {c['name']} ». "
                           "Relancer les utilisateurs en retard.",
            "status": "planifie",
            "due_date": due,
            "severity": "moyenne",
            "assignee": "",
            "entity_name": c["name"],
            "source": "proofpoint_psat",
        }
        if sid in existing:
            existing[sid].data = data
            existing[sid].entity_name = c["name"]
            existing[sid].synced_at = now
        else:
            db.add(MeasureCache(
                module="pilot", source_id=sid, entity_id="psat",
                entity_name=c["name"], data=data, synced_at=now,
            ))

    for sid, r in existing.items():
        if sid not in active and (r.data or {}).get("status") != "termine":
            d = dict(r.data or {})
            d["status"] = "termine"
            r.data = d

    await db.commit()
    return len(active)


# ---------- KPIs (one per training campaign) ------------------------------ #

_KPI_PREFIX = "psat.completion."

# Default framework control anchors for a PSAT (awareness/training) KPI. Seeded
# once at KPI creation so every completion indicator ships pre-mapped to the
# relevant "security awareness & training" requirements; an admin can then
# refine them (add via AI suggestions, remove) and the connector won't overwrite.
_DEFAULT_FRAMEWORKS: list[tuple[str, str, str, str]] = [
    ("ISO_27001_2022", "A.6.3",
     "Sensibilisation, enseignement et formation à la sécurité de l'information",
     "Information security awareness, education and training"),
    ("NIST_CSF_2", "PR.AT-01",
     "Le personnel est sensibilisé et formé",
     "Personnel are provided with awareness and training"),
    ("CIS_v8", "14",
     "Formation à la sensibilisation et aux compétences en sécurité",
     "Security Awareness and Skills Training"),
    ("NIS2", "Art.21.2.g",
     "Cyberhygiène de base et formation à la sécurité",
     "Basic cyber hygiene practices and security training"),
    ("DORA", "Art.13.6",
     "Programmes de sensibilisation et formation à la sécurité TIC",
     "ICT security awareness programmes and training"),
]


def _kpi_code(name: str) -> str:
    """Stable KPI code, guaranteed to fit ``kpi_definition.code`` (varchar 64).
    Short names keep their plain ``psat.completion.<slug>`` code unchanged; long
    names keep a readable slug head plus an 8-char hash so they neither overflow
    nor collide."""
    slug = _campaign_slug(name)
    code = _KPI_PREFIX + slug
    if len(code) <= 64:
        return code
    h = hashlib.sha256(_norm(name).encode()).hexdigest()[:8]
    head = 64 - len(_KPI_PREFIX) - 1 - len(h)
    return _KPI_PREFIX + slug[:head] + "-" + h


def _kpi_name(name: str, limit: int = 180) -> str:
    """Truncate a campaign name so ``Sensibilisation — {name}`` fits name_fr (200)."""
    n = str(name or "")
    return n if len(n) <= limit else n[: limit - 1].rstrip() + "…"


async def _sync_kpis(reporting: dict, db: AsyncSession) -> int:
    """Maintain one external KPI per tracked campaign (completion %) and ingest
    its current value as a daily KpiSnapshot. Campaigns no longer tracked are
    deactivated (kept for history). The KPI carries connector_config so the KPI
    detail modal can render the per-campaign overdue list (FEAT-18)."""
    from src.routes.kpis import _ingest  # lazy — avoids import cycle

    today = datetime.now(timezone.utc)
    bucket = datetime(today.year, today.month, today.day, tzinfo=timezone.utc)
    active_codes: set[str] = set()

    for c in reporting.get("campaigns", []):
        slug = c.get("slug") or _campaign_slug(c["name"])
        code = _kpi_code(c["name"])
        active_codes.add(code)
        disp = _kpi_name(c["name"])
        cfg = {"detail": "awareness", "campaign": c["name"], "slug": slug,
               "due_date": c.get("due_date", ""), "grace_date": c.get("grace_date", ""),
               "severity": c.get("severity", "")}
        existing = (await db.execute(
            select(KpiDefinition).where(KpiDefinition.code == code)
        )).scalar_one_or_none()
        if existing:
            existing.name_fr = f"Sensibilisation — {disp}"
            existing.name_en = f"Awareness — {disp}"
            existing.connector_config = cfg
            existing.active = True
            kpi = existing
        else:
            kpi = KpiDefinition(
                code=code,
                name_fr=f"Sensibilisation — {disp}",
                name_en=f"Awareness — {disp}",
                description_fr=f"Taux de complétion de la formation « {c['name']} » (Proofpoint).",
                description_en=f"Completion rate of the « {c['name']} » training (Proofpoint).",
                category_primary="protect",
                unit="%",
                direction="higher_better",
                source_type="external",
                source_module="connector",
                source_metric="psat_completion",
                connector_config=cfg,
                target=100, threshold_amber=80, threshold_red=60,
                active=True,
            )
            db.add(kpi)
        await db.flush()
        # Seed the default awareness framework anchors when the KPI has none yet
        # (fresh KPI, or an existing one not yet mapped) — never overwrite an
        # admin's chosen mappings.
        has_map = (await db.execute(
            select(KpiFrameworkMapping.id).where(KpiFrameworkMapping.kpi_id == kpi.id).limit(1)
        )).first()
        if not has_map:
            for fw, ref, lfr, len_ in _DEFAULT_FRAMEWORKS:
                db.add(KpiFrameworkMapping(
                    kpi_id=kpi.id, framework_code=fw, ref_code=ref,
                    ref_label_fr=lfr, ref_label_en=len_,
                ))
        # Ingest the current completion % (daily bucket, last-pass-wins).
        await _ingest(
            db, code=code, value=float(c.get("pct") or 0.0),
            captured_at=bucket, source="auto", note=None,
            raw_payload={"assigned": c.get("assigned"), "completed": c.get("completed")},
        )

    # Deactivate KPIs for campaigns that are no longer tracked, and migrate any
    # legacy "Complétion —" title to "Sensibilisation —" (incl. historical ones).
    stale = (await db.execute(
        select(KpiDefinition).where(KpiDefinition.code.like(_KPI_PREFIX + "%"))
    )).scalars().all()
    for k in stale:
        if k.code not in active_codes and k.active:
            k.active = False
        if k.name_fr and k.name_fr.startswith("Complétion — "):
            k.name_fr = "Sensibilisation — " + k.name_fr[len("Complétion — "):]
        if k.name_en and k.name_en.startswith("Completion — "):
            k.name_en = "Awareness — " + k.name_en[len("Completion — "):]
    await db.commit()
    return len(active_codes)


# ---------- Connector entry points (test / run) --------------------------- #

async def test_credentials(db: AsyncSession) -> tuple[bool, str]:
    cfg = await get_config(db)
    if not cfg["api_key"]:
        if await _demo_enabled(db):
            return True, "Mode démo (aucune clé API PSAT) — données simulées sur l'annuaire Access."
        return False, "Aucune clé API PSAT configurée."
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=_headers(cfg["api_key"])) as client:
            resp = await client.get(_base_url(cfg["region"]) + "/training",
                                    params={"page[size]": 1, "page[number]": 1})
        if resp.status_code in (401, 403):
            return False, "Clé API PSAT refusée (401/403)."
        resp.raise_for_status()
        return True, f"Connecté à PSAT ({cfg['region'].upper()})."
    except Exception as e:  # noqa: BLE001
        logger.warning("PSAT test failed: %s", e)
        return False, "Échec de connexion à l'API PSAT (voir les logs serveur)."


async def run_sync(db: AsyncSession) -> dict[str, Any]:
    """Pull training completion and push the Access awareness proof.
    Lot 2 (KPIs/panel) and Lot 3 (measures) hook in here later."""
    cfg = await get_config(db)
    # No-op until configured — keeps the scheduled call harmless on a fresh
    # install (and avoids demo-synth noise when nothing is set up).
    if not cfg["tracked_campaigns"] and not cfg["campaign_filter"]:
        return {"ok": False, "skipped": "not configured (no campaign filter or list)"}

    demo = not cfg["api_key"]
    today = datetime.now(timezone.utc).date().isoformat()
    meta: dict[str, dict] = {}

    if demo:
        if not await _demo_enabled(db):
            return {"ok": False, "skipped": "not configured (no API key, demo disabled)"}
        effective = cfg["tracked_campaigns"]
        if not effective:
            return {"ok": False, "skipped": "demo mode needs an explicit campaign list (no live data to discover from)"}
        users = await _demo_users(cfg, effective, db)
    else:
        try:
            records = await _fetch_all("/training", cfg)
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code == 429:
                msg = "Limite de débit de l'API PSAT atteinte (429). Réessayez dans quelques minutes."
            elif code in (401, 403):
                msg = "Clé API PSAT refusée (401/403)."
            else:
                msg = f"Échec de l'API PSAT (HTTP {code})."
            logger.warning("PSAT run live fetch failed: %s", e)
            return {"ok": False, "error": msg}
        except httpx.HTTPError as e:
            logger.warning("PSAT run live fetch error: %s", e)
            return {"ok": False, "error": "Échec de connexion à l'API PSAT (voir les logs serveur)."}
        meta = _campaign_meta(records)
        if cfg["campaign_filter"]:
            effective = _discover_campaigns(meta, cfg["campaign_filter"], today, cfg["retention_months"])
            if not effective:
                return {"ok": False, "skipped": f"aucune formation en cours ne correspond au filtre « {cfg['campaign_filter']} »"}
        else:
            effective = cfg["tracked_campaigns"]
        users = _parse_training(records, effective)

    # Mandatory campaigns default to the whole effective set (the discovered /
    # tracked trainings) — no separate explicit list in the UI anymore. An
    # env-var still overrides if an ops user wants a stricter subset.
    mandatory = cfg["mandatory_campaigns"] or effective
    cfg["mandatory_campaigns"] = mandatory

    # (1) Access proof feed — domain + mandatory filtered.
    payload = _build_access_payload(users, cfg, today)
    access_result = await _push_access(db, payload) if payload else {"pushed": 0}

    # (2) Reporting — tenant-wide, per campaign + daily trend point.
    reporting = _build_reporting(users, effective, mandatory, today)
    await _store_detail(reporting, db)

    # (3) KPIs — one completion KPI per tracked campaign (+ daily snapshot).
    kpis_synced = await _sync_kpis(reporting, db)

    # (4) Action plan — overdue-cohort measures.
    measures_raised = await _sync_measures(reporting, db)

    summary = {
        "ok": True,
        "mode": "demo" if demo else "live",
        "region": cfg["region"],
        "users_seen": len(users),
        "access_candidates": len(payload),
        "access_result": access_result,
        "overall_completion_pct": reporting["overall_completion_pct"],
        "overdue_total": reporting["overdue_total"],
        "completed_late": sum(c["completed_late"] for c in reporting["campaigns"]),
        "kpis_synced": kpis_synced,
        "measures_raised": measures_raised,
        "campaign_filter": cfg["campaign_filter"],
        "tracked_campaigns": effective,
        "mandatory_campaigns": cfg["mandatory_campaigns"],
    }
    logger.info("PSAT run: %s", summary)
    return summary
