"""Digest — vulnerability digest (structured) + threat brief (free-prompt LLM).

Two independent emails per scope:

  * **Vulnerability digest** — driven by deterministic CPE/PURL/keyword
    matches on the CVE feeds (NVD, OSV, KEV, GHSA, CERT-FR…). Window
    is "since last successful digest" for the (scope, recipient) pair;
    a 7-day look-back is used on first run. Inclusion thresholds live
    on :class:`Scope` (``digest_severity_min`` / ``digest_include_kev`` /
    ``digest_cvss_min`` / ``digest_epss_min``) combined with OR
    semantics by :func:`digest_filter.passes_threshold`. Duplicate
    CVE rows are folded into :class:`digest_grouping.AlertGroup` and
    each card is enriched with an LLM-generated 8-section analysis,
    cached in :class:`AlertAnalysis` by ``(alert_id, content_hash,
    language)``.
  * **Threat brief** (M22) — free-form CISO context written by the
    user as ``Scope.threat_prompt``. At send time we hand the prompt
    to Claude with Anthropic's ``web_search`` tool (max 5 searches),
    asking for relevant news on the last ``threat_search_window_days``
    days. The HTML brief plus source citations are pasted into the
    email. No matcher, no scorer, no topic tables — the LLM does the
    triage. Empty ``threat_prompt`` disables the threat brief for that
    scope.

Skipped-empty stamps keep the "since" window advancing without
sending empty mail. The send loop is per-tick, per-scope, per-
recipient, SMTP best-effort.
"""
from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import uuid
from datetime import datetime, timedelta, timezone
from html import escape as h_esc

from src.html_sanitize import safe_url, sanitize_html
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from sqlalchemy import and_, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.analysis import generate_or_get
from src.database import async_session
from src.digest_filter import passes_threshold, digest_suppressed
from src.digest_grouping import AlertGroup, group_alerts
from src.mailer_common import resolve_pushed_config, send_html_email
from src.models import (
    Alert, AlertAnalysis, AlertMatch, AlertStatus, DigestRun, Scope,
    ScopeRecipient, User,
)

logger = logging.getLogger("watch-digest")

def _public_base() -> str:
    """Absolute base for the "view in app" links of the digest.

    The suite-wide name is ``PUBLIC_BASE_URL`` — pilot, appsec and surface all
    read that one. Watch shipped reading ``PUBLIC_URL`` only, so a deployment
    configured the documented way produced a digest with no links at all while
    every other module's mails were fine. ``PUBLIC_URL`` stays accepted as a
    fallback so installs already relying on it keep working.
    """
    return (os.getenv("PUBLIC_BASE_URL", "") or os.getenv("PUBLIC_URL", "")).rstrip("/")

# Look-back window when a recipient has never received a digest before.
# Long enough to surface the recent ATH backlog, short enough not to
# spam with months-old advisories the recipient probably already triaged.
_FIRST_RUN_LOOKBACK_DAYS = int(os.getenv("WATCH_FIRST_RUN_LOOKBACK_DAYS", "7"))

# Digest output language for v2. The analysis module already supports
# "en" for when we add a per-scope locale.
_DIGEST_LANGUAGE = "fr"


def _smtp_settings() -> dict:
    """Resolve SMTP config: Pilot in-memory push > env vars (standalone).

    Thin wrapper over the shared resolver — see ``src.mailer_common``.
    """
    try:
        from src.routes.internal import _smtp_config as pushed
    except Exception:
        pushed = {}
    return resolve_pushed_config(pushed, "watch@cisotoolbox.local")

# Match window for "is it digest time?". Must be ≥ scheduler tick interval
# so we don't miss a window when the tick lands just before the configured
# time. 60s safety pad on top of the tick, capped at 30 min.
_TICK_SECONDS = int(os.getenv("WATCH_TICK_SECONDS", "900"))
LENIENCY_MINUTES = max(5, min(30, _TICK_SECONDS // 60 + 1))


def _tz(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name or "Europe/Paris")
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def _now_local(tz_name: str) -> datetime:
    return datetime.now(timezone.utc).astimezone(_tz(tz_name))


def _within_window(
    now_utc: datetime, tz_name: str, hour: int, minute: int
) -> bool:
    """Return True when ``now_utc`` falls within ``LENIENCY_MINUTES`` of
    the configured local hour:minute in ``tz_name``.

    Factored out so the vulnerability digest and the threat digest
    share the exact same window semantics — the only thing that
    differs between the two is which scope columns drive it.
    """
    tz = _tz(tz_name or "Europe/Paris")
    local = now_utc.astimezone(tz)
    target_local = local.replace(
        hour=int(hour), minute=int(minute), second=0, microsecond=0,
    )
    delta = (local - target_local).total_seconds()
    return 0 <= delta <= LENIENCY_MINUTES * 60


def _is_due(target, now_utc: datetime) -> bool:
    """True if ``target``'s **vulnerability** digest window is open.

    Reads the legacy ``digest_*`` columns. Kept named ``_is_due``
    (instead of ``_is_vuln_due``) for backwards compatibility — the
    preview route and tests reference this name.
    """
    if not getattr(target, "digest_enabled", True):
        return False
    # NB: `or 7` would map digest_hour=0 (midnight) to 7am — use explicit
    # None check so hour=0 / minute=0 remain themselves.
    h_raw = getattr(target, "digest_hour", None)
    m_raw = getattr(target, "digest_minute", None)
    return _within_window(
        now_utc,
        getattr(target, "digest_timezone", None) or "Europe/Paris",
        int(h_raw) if h_raw is not None else 7,
        int(m_raw) if m_raw is not None else 0,
    )


def _is_threat_due(scope: Scope, now_utc: datetime) -> bool:
    """True if ``scope``'s **threat-watch** digest window is open.

    Independent from the vulnerability digest: reads ``threat_digest_*``
    columns added in migration 010. Honours daily/weekly/off cadence:

    * ``off`` (or ``threat_digest_enabled=False``) — never fires.
    * ``daily`` — fires once a day at ``threat_digest_hour:minute`` local.
    * ``weekly`` — same window but only on ``threat_digest_weekday``
      (0 = Monday, … 6 = Sunday).
    * empty ``threat_prompt`` — no prompt to feed Claude, nothing to send.

    ``DigestRun.kind='threat'`` + the per-kind unique constraint
    (uq_digest_user_scope_kind_date) prevent a same-day double-send.
    """
    if not getattr(scope, "threat_digest_enabled", True):
        return False
    if not (getattr(scope, "threat_prompt", "") or "").strip():
        return False
    freq = (getattr(scope, "threat_digest_frequency", "weekly") or "weekly").lower()
    if freq == "off":
        return False
    tz_name = getattr(scope, "threat_digest_timezone", None) or "Europe/Paris"
    tz = _tz(tz_name)
    local = now_utc.astimezone(tz)
    if freq == "weekly":
        weekday = int(getattr(scope, "threat_digest_weekday", 0) or 0)
        if local.weekday() != weekday:
            return False
    h_raw = getattr(scope, "threat_digest_hour", None)
    m_raw = getattr(scope, "threat_digest_minute", None)
    return _within_window(
        now_utc,
        tz_name,
        int(h_raw) if h_raw is not None else 8,
        int(m_raw) if m_raw is not None else 0,
    )


async def _last_sent_at(
    db: AsyncSession, email: str, scope_id: uuid.UUID
) -> datetime | None:
    """Most recent ``sent_at`` for a successful digest delivered to
    ``email`` for ``scope_id``. Returns None when no digest has ever
    been sent to this recipient for this scope.
    """
    row = (await db.execute(
        select(func.max(DigestRun.sent_at)).where(
            DigestRun.user_email == email,
            DigestRun.scope_id == scope_id,
            DigestRun.status == "sent",
        )
    )).scalar_one_or_none()
    return row


async def _user_scopes(db: AsyncSession, user: Optional[User]) -> list[Scope]:
    """Scopes visible to ``user`` (owned + recipient on). Kept for the
    preview endpoint which renders the digest from a user's perspective.

    ``user is None`` means auth is disabled (see THE `None` CONTRACT in
    src/auth_common.py): no identity to filter on, caller is admin, so
    every scope is visible.
    """
    if user is None:
        return list((await db.execute(select(Scope))).scalars().all())
    owned = (await db.execute(select(Scope).where(Scope.owner_id == user.id))).scalars().all()
    shared_ids = (await db.execute(
        select(ScopeRecipient.scope_id).where(ScopeRecipient.email == (user.email or "").lower())
    )).scalars().all()
    shared: list[Scope] = []
    if shared_ids:
        shared = (await db.execute(select(Scope).where(Scope.id.in_(shared_ids)))).scalars().all()
    out: dict[uuid.UUID, Scope] = {s.id: s for s in owned}
    for s in shared:
        out.setdefault(s.id, s)
    return list(out.values())


async def _alerts_for_scope(
    db: AsyncSession, user: User | None, scope: Scope, since: datetime
) -> list[Alert]:
    """Alerts touching ``scope`` since ``since``, filtered by the
    scope's digest thresholds. When ``user`` is given and has an
    ``AlertStatus`` row marking an alert dismissed/resolved, that alert
    is filtered out of the returned list (per-recipient triage).
    """
    pairs = (await db.execute(
        select(Alert, AlertMatch.match_kind)
        .join(AlertMatch, AlertMatch.alert_id == Alert.id)
        .where(
            AlertMatch.scope_id == scope.id,
            AlertMatch.matched_at >= since,
        )
        .order_by(Alert.severity.desc(), Alert.cvss_score.desc().nullslast())
    )).all()
    # Pure-Python filters — at most a few hundred rows per scope per tick,
    # no need to push them into SQL. An alert stays in the digest if at
    # least one of its in-window matches is not suppressed (backfill or
    # NVD-modified re-match of a CVE known before the window).
    rows = []
    seen: set = set()
    for a, mk in pairs:
        if a.id in seen or digest_suppressed(mk, a.kev_listed_at, a.ingested_at, since):
            continue
        seen.add(a.id)
        rows.append(a)
    rows = [a for a in rows if passes_threshold(a, scope)]
    if not rows or user is None:
        return list(rows)

    dismissed = set((await db.execute(
        select(AlertStatus.alert_id).where(
            AlertStatus.user_id == user.id,
            AlertStatus.alert_id.in_([a.id for a in rows]),
            AlertStatus.status.in_(("dismissed", "resolved")),
        )
    )).scalars().all())
    return [a for a in rows if a.id not in dismissed]


def _sev_color(s: str) -> str:
    return {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
            "low": "#95a5a6"}.get((s or "").lower(), "#bdc3c7")


def _sev_label_fr(s: str) -> str:
    return {"critical": "CRITIQUE", "high": "ÉLEVÉ",
            "medium": "MOYEN", "low": "FAIBLE"}.get((s or "").lower(), "INCONNU")


_URGENCY_LABEL_FR = {
    "PATCH_IMMEDIATELY": "PATCHER IMMÉDIATEMENT",
    "PATCH_WITHIN_24H": "PATCHER SOUS 24 H",
    "PATCH_WITHIN_72H": "PATCHER SOUS 72 H",
    "PATCH_THIS_WEEK": "PATCHER CETTE SEMAINE",
    "PATCH_THIS_MONTH": "PATCHER CE MOIS",
    "NEXT_CYCLE": "PROCHAIN CYCLE",
}


def _urgency_label_fr(u: str) -> str:
    return _URGENCY_LABEL_FR.get(u or "", "—")


def _alert_link(alert_id: uuid.UUID) -> str:
    base = _public_base()
    return f"{base}/watch/#alerts/{alert_id}" if base else ""


def _render_group_card(
    group: AlertGroup, analysis: AlertAnalysis | None
) -> str:
    """Render one vulnerability card (severity bandeau + analysis sections)."""
    a = group.primary
    sev_bg = _sev_color(group.severity)
    sev_label = _sev_label_fr(group.severity)
    kev_chip = (
        ' <span style="background:#fff;color:#c0392b;padding:1px 8px;'
        'border-radius:10px;font-size:11px;font-weight:600;'
        'margin-left:8px;border:1px solid #fff">KEV — exploité</span>'
    ) if group.kev_listed else ""
    # M13 — ransomware-campaign flag (CISA-curated, "Known" on KEV row).
    ransomware_chip = (
        ' <span style="background:#000;color:#fff;padding:1px 8px;'
        'border-radius:10px;font-size:11px;font-weight:700;'
        'margin-left:8px;border:1px solid #000">RANÇONGICIEL</span>'
    ) if group.ransomware_known else ""
    urgency_chip = (
        f' <span style="background:rgba(255,255,255,0.18);color:#fff;'
        f'padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;'
        f'margin-left:8px;border:1px solid rgba(255,255,255,0.4)">'
        f'{h_esc(_urgency_label_fr(group.urgency))} · risque {group.risk_score:.0f}'
        f'</span>'
    )
    cvss = f"{group.max_cvss:.1f}" if group.max_cvss is not None else "—"
    epss_txt = ""
    if group.max_epss is not None:
        epss_txt = f' · EPSS {group.max_epss * 100:.1f}%'
    sources = ", ".join(s.upper() for s in group.sources) or "—"
    cve = group.cve_id or f"{a.source}:{a.external_id}"
    link = _alert_link(a.id)
    link_html = (
        f'<a href="{h_esc(link)}" '
        'style="color:#fff;text-decoration:underline">Voir dans Watch →</a>'
    ) if link else ""

    sections = (analysis.sections if analysis else {}) or {}

    def _sec(label: str, key: str) -> str:
        val = sections.get(key) or ""
        if not val or val.strip().lower() == "unknown":
            return ""
        # Recommended actions arrive as " | "-joined bullets — split for display.
        if key == "recommended_actions" and " | " in val:
            items = [b.strip() for b in val.split(" | ") if b.strip()]
            body = (
                "<ul style='margin:6px 0 0 18px;padding:0'>"
                + "".join(f"<li style='margin:2px 0'>{h_esc(b)}</li>" for b in items)
                + "</ul>"
            )
        elif key == "references_curated" and " | " in val:
            urls = [u.strip() for u in val.split(" | ") if u.strip()]
            body = "<div style='margin-top:6px'>" + " · ".join(
                f'<a href="{h_esc(safe_url(u))}" style="color:#2c3e50">{h_esc(u)}</a>'
                for u in urls if safe_url(u)
            ) + "</div>"
        else:
            body = f"<div style='margin-top:6px'>{h_esc(val)}</div>"
        return (
            f"<div style='margin-top:14px'>"
            f"<div style='font-size:12px;text-transform:uppercase;"
            f"color:#7f8c8d;font-weight:600;letter-spacing:0.5px'>{h_esc(label)}</div>"
            f"{body}"
            f"</div>"
        )

    # M13 — timeline strip: NVD pub date, KEV add date, patch-lag/exploit window.
    tl = group.timeline
    tl_items: list[str] = []
    if tl.nvd_published is not None:
        tl_items.append(
            f'<span><b>Publié NVD :</b> {h_esc(tl.nvd_published.strftime("%Y-%m-%d"))}</span>'
        )
    if tl.kev_date_added is not None:
        tl_items.append(
            f'<span><b>Ajout KEV :</b> {h_esc(tl.kev_date_added.strftime("%Y-%m-%d"))}</span>'
        )
    if tl.patch_lag_days is not None:
        tl_items.append(
            f'<span><b>Délai NVD→KEV :</b> {tl.patch_lag_days} j</span>'
        )
    if tl.ransomware_label:
        tl_items.append(
            f'<span><b>Rançongiciel :</b> {h_esc(tl.ransomware_label)}</span>'
        )
    timeline_html = ""
    if tl_items:
        timeline_html = (
            f"<div style='margin-top:10px;padding:6px 10px;background:#f8f9fa;"
            f"border-left:3px solid #95a5a6;font-size:12px;color:#555;"
            f"display:flex;gap:14px;flex-wrap:wrap'>"
            + "".join(tl_items)
            + f"</div>"
        )

    body_html = "".join([
        _sec("Synthèse", "executive_summary"),
        _sec("Détail technique", "technical_detail"),
        _sec("Exploitation", "exploitation_status"),
        _sec("Composants affectés", "affected_components"),
        _sec("Impact métier", "business_impact"),
        _sec("Actions recommandées", "recommended_actions"),
        _sec("Références", "references_curated"),
    ])
    if not body_html:
        # No analysis yet — render the raw summary as a fallback so the
        # card isn't empty.
        body_html = (
            f"<div style='margin-top:10px;color:#555'>"
            f"{h_esc((a.summary or '')[:600])}</div>"
        )
    # Timeline strip (M13) always sits above the analysis sections.
    body_html = timeline_html + body_html

    return (
        f'<div style="border:1px solid #e0e0e0;border-radius:8px;'
        f'margin:18px 0;overflow:hidden;background:#fff">'
        # Severity bandeau
        f'<div style="background:{sev_bg};color:#fff;padding:10px 16px;'
        f'display:flex;justify-content:space-between;align-items:center">'
        f'<div>'
        f'<span style="font-weight:700;letter-spacing:0.5px">{h_esc(sev_label)}</span>'
        f'{urgency_chip}'
        f'{kev_chip}'
        f'{ransomware_chip}'
        f'<span style="margin-left:14px;font-size:13px;opacity:0.95">'
        f'CVSS {h_esc(cvss)}{h_esc(epss_txt)}</span>'
        f'</div>'
        f'<div style="font-size:12px;opacity:0.9">{link_html}</div>'
        f'</div>'
        # Title block
        f'<div style="padding:14px 16px 0 16px">'
        f'<div style="font-family:monospace;font-size:12px;color:#7f8c8d">'
        f'{h_esc(cve)} · {h_esc(sources)}</div>'
        f'<div style="font-weight:600;font-size:16px;margin-top:4px;color:#2c3e50">'
        f'{h_esc((a.title or "")[:300])}</div>'
        # Analysis sections
        f'<div style="padding:0 0 14px 0">{body_html}</div>'
        f'</div>'
        f'</div>'
    )



def _wrap_html(greeting: str, intro: str, section: str) -> str:
    """Common email shell (greeting + intro + one section + footer)."""
    return f"""<!doctype html><html><body style="font-family:Arial,sans-serif;color:#222;line-height:1.5;background:#f5f5f5;margin:0;padding:0">
<div style="max-width:760px;margin:0 auto;padding:24px;background:#f5f5f5">
<p>{greeting}</p>
<p>{intro}</p>
{section}
<p style="color:#888;font-size:12px;margin-top:32px;border-top:1px solid #ddd;padding-top:14px">
CISO Toolbox · Watch — digest envoyé automatiquement. Seuils configurables dans les paramètres du périmètre.
</p>
</div>
</body></html>"""


def _greeting(user_name: str) -> str:
    return f"Bonjour {h_esc(user_name)}," if user_name else "Bonjour,"


def _since_txt(since: datetime | None) -> str:
    return (
        since.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if since else "depuis le démarrage de la veille"
    )


def render_vuln_digest_html(
    scope_name: str,
    groups: list[AlertGroup],
    analyses: dict[uuid.UUID, AlertAnalysis],
    user_name: str = "",
    since: datetime | None = None,
) -> str:
    """Vulnerability-only digest body (M18).

    Independent of the threat digest — fires on the legacy ``digest_*``
    cadence and only contains the "Vulnérabilités critiques" section.
    """
    intro = (
        f"Voici le digest <strong>Vulnérabilités</strong> du périmètre "
        f"<strong>{h_esc(scope_name)}</strong> depuis le précédent digest "
        f"({h_esc(_since_txt(since))})."
    )
    if groups:
        cards = "".join(
            _render_group_card(g, analyses.get(g.primary.id))
            for g in groups
        )
        section = (
            f'<h2 style="color:#2c3e50;border-bottom:2px solid #c0392b;'
            f'padding-bottom:6px;margin-top:28px">'
            f'Vulnérabilités critiques ({len(groups)})</h2>'
            f'{cards}'
        )
    else:
        section = (
            f'<h2 style="color:#2c3e50;border-bottom:2px solid #c0392b;'
            f'padding-bottom:6px;margin-top:28px">Vulnérabilités critiques</h2>'
            f'<div style="padding:14px;color:#7f8c8d;background:#fafafa;'
            f'border:1px dashed #ddd;border-radius:6px">'
            f'Aucune vulnérabilité critique n\'a été publiée dans votre périmètre depuis le précédent digest.'
            f'</div>'
        )
    return _wrap_html(_greeting(user_name), intro, section)


# System prompts for the threat-brief LLM call.
#
# The FR prompt is the canonical "threat-watch-rssi" skill methodology
# (sector-mandatory queries, source authority grid, supply-chain checks,
# honest triage). It is stored as a Markdown file in src/prompts/ so it
# can be edited without touching the Python module, and so the user can
# diff it directly against the .skill zip at watch/threat-watch-rssi.skill.
#
# The EN prompt remains inlined below — keep it in sync with the FR
# skill on output format (HTML structure, allowed tags, source rules);
# the methodology rules carry less weight in EN since the skill itself
# is French-only.

_PROMPTS_DIR = pathlib.Path(__file__).parent / "prompts"


def _load_prompt(name: str) -> str:
    """Read a prompt file from src/prompts/. Falls back to empty string
    if the file is missing — the threat-brief route then surfaces a
    visible "no system prompt" error via the LLM rather than crashing.
    """
    path = _PROMPTS_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("could not load prompt %s: %s", name, e)
        return ""


_THREAT_BRIEF_SYSTEM_FR = _load_prompt("threat_brief_skill_fr.md")


_THREAT_BRIEF_SYSTEM_EN = """You are a cyber threat-intelligence analyst writing
a weekly watch note for a CISO.

You receive:
  - the CISO's CONTEXT (stack, sector, constraints)
  - the CURRENT DATE and a time WINDOW (in days) to cover
  - the ``web_search`` tool to fetch up-to-date information

You produce an operational note in simple HTML. Each item should be readable
in 20 seconds and end on a dated action. Mandatory structure:

  <h2 style="color:#c0392b;margin-top:24px">🔴 Priority 1 — Immediate action (24-48h)</h2>
  <h3><b>Short title</b> — short reason it matters in this context</h3>
  <p>2-4 sentence description: what happened, mechanism, concrete impact on the CISO's stack.</p>
  <ul>
    <li><b>CVE:</b> CVE-YYYY-NNNN (CVSS X.X) — when applicable</li>
    <li><b>IOC:</b> concrete file paths / domains / IPs / hashes when known</li>
    <li><b>Action:</b> 1-3 concrete actions with deadlines (e.g. "audit lockfiles today")</li>
  </ul>
  <p style="margin:6px 0 14px;font-size:11px;color:#666">Sources: <a href="URL1">domain1</a>, <a href="URL2">domain2</a></p>

  <h2 style="color:#e67e22;margin-top:24px">🟠 Priority 2 — Within 7 days</h2>
  …same structure (h3 + p + ul CVE/IOC/Action + p Sources)…

  <h2 style="color:#f1c40f;margin-top:24px">🟡 Priority 3 — Within the month</h2>
  …same structure…

  <h2 style="color:#2c3e50;margin-top:24px">📌 Sector context</h2>
  <p>2-4 trends specific to the CISO's sector over the period (ransomware, fraud, social engineering, deepfake, etc.) with concrete implications.</p>
  <p style="margin:6px 0 14px;font-size:11px;color:#666">Sources: <a href="URL">…</a></p>

  <h2 style="color:#27ae60;margin-top:24px">✅ Action plan — summary</h2>
  <table style="border-collapse:collapse;width:100%;font-size:13px">
    <thead><tr style="background:#ecf0f1"><th style="text-align:left;padding:6px;border:1px solid #ddd">Priority</th><th style="text-align:left;padding:6px;border:1px solid #ddd">Action</th><th style="text-align:left;padding:6px;border:1px solid #ddd">Deadline</th></tr></thead>
    <tbody><tr><td style="padding:6px;border:1px solid #ddd">P1</td><td style="padding:6px;border:1px solid #ddd">…</td><td style="padding:6px;border:1px solid #ddd">…</td></tr>…</tbody>
  </table>

Strict rules:
  - Stay within the indicated time window (CURRENT DATE is provided).
  - Always include supply-chain compromises (npm, PyPI, GitHub Actions,
    Docker registries, etc.) and actively exploited zero-days that affect
    any language / runtime / product mentioned in the CISO's stack, EVEN
    if the CISO did not name them explicitly.
  - Honest triage: if nothing rises to P1, do not invent — leave the P1
    section with a single line ("No P1-level threat in this period.").
  - At most 4 items per priority bucket — more becomes diluted noise.
  - Provide a CVE id + CVSS score when the item is a vulnerability.
  - Provide at least 1 concrete IOC when known (path, domain, IP, hash).
  - Each action must be executable as-is (command, path, step).
  - End every <h2> section with <p style="margin:6px 0 14px;font-size:11px;color:#666">Sources: <a href="URL">domain</a>, …</p>
    listing the URLs actually used in that section (link text = domain).
  - Allowed HTML only: <h2>, <h3>, <p>, <ul>, <li>, <b>, <table>, <thead>, <tbody>, <tr>, <th>, <td>, <a>.
  - No markdown, no <html>, <body>, <script>, <style>, <iframe>.
  - No emojis other than section headers (🔴 🟠 🟡 📌 ✅)."""


# Hard guard prepended to whichever language prompt we use. Models with
# web_search love to narrate ("Je vais lancer les recherches…", "Voici le
# rapport"), and that chatter then leaks into the email body. We say it
# again here, in both languages, on top of what the skill file already
# says — and we still strip post-hoc (see ``_strip_llm_chatter``).
_THREAT_BRIEF_NO_PREAMBLE = (
    "RÈGLE ABSOLUE DE SORTIE / OUTPUT RULE — ANSWER WITH HTML ONLY.\n"
    "Ne dis pas \"je vais chercher\", \"voici le rapport\", \"---\", etc. "
    "Do NOT narrate the workflow, do NOT introduce, do NOT conclude. "
    "La toute première chose de ta réponse doit être un tag HTML "
    "(<p>, <h2>, <table>, …). The first character of your answer "
    "MUST be '<'. No prose before, no prose after.\n\n"
)


def _threat_brief_system(language: str) -> str:
    body = (
        _THREAT_BRIEF_SYSTEM_FR
        if (language or "fr").lower().startswith("fr")
        else _THREAT_BRIEF_SYSTEM_EN
    )
    return _THREAT_BRIEF_NO_PREAMBLE + body


# Tags we consider valid "real content" openings — first one wins.
_HTML_START_TAGS = ("<p", "<h1", "<h2", "<h3", "<h4", "<table", "<ul", "<ol", "<div")
# Closing tags that mark legit end-of-brief — anything after the last one
# is chatter ("Le rapport ci-dessus couvre…").
_HTML_END_TAGS = ("</p>", "</h1>", "</h2>", "</h3>", "</h4>", "</table>", "</ul>", "</ol>", "</div>")


def _strip_llm_chatter(html: str) -> str:
    """Trim LLM narration before/after the real HTML brief.

    Claude with ``web_search`` regularly prepends ``Je vais lancer les
    recherches en parallèle…`` and appends ``Voici le rapport complet en
    HTML : ---`` or similar workflow narration. Despite an explicit system
    instruction the chatter still slips through on some runs, so we strip
    it post-hoc:

      * Crop everything before the first allow-listed opening tag.
      * Crop everything after the last allow-listed closing tag.

    If no opening tag is found we return the input unchanged — better to
    show *something* than an empty brief.
    """
    if not html:
        return html
    s = html.strip()

    # Leading chatter: find earliest allow-listed opening tag.
    first = -1
    for tag in _HTML_START_TAGS:
        i = s.find(tag)
        if i >= 0 and (first < 0 or i < first):
            first = i
    if first > 0:
        s = s[first:]

    # Trailing chatter: cut after the last allow-listed closing tag.
    last_end = -1
    for tag in _HTML_END_TAGS:
        i = s.rfind(tag)
        if i >= 0:
            end = i + len(tag)
            if end > last_end:
                last_end = end
    if last_end > 0 and last_end < len(s):
        s = s[:last_end]

    return s.strip()


def _threat_brief_user(prompt: str, window_days: int, language: str) -> str:
    """Build the user-message body fed to Claude alongside the system prompt."""
    today_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if (language or "fr").lower().startswith("fr"):
        return (
            f"DATE COURANTE : {today_iso} (UTC).\n"
            f"FENÊTRE : {int(window_days)} derniers jours uniquement.\n\n"
            f"CONTEXTE (rédigé par le RSSI) :\n{prompt.strip()}\n\n"
            f"Produis la note en français en suivant strictement la structure imposée "
            f"(P1/P2/P3 + contexte sectoriel + tableau plan d'action, sources par section)."
        )
    return (
        f"CURRENT DATE: {today_iso} (UTC).\n"
        f"WINDOW: last {int(window_days)} days only.\n\n"
        f"CONTEXT (written by the CISO):\n{prompt.strip()}\n\n"
        f"Write the note in English following the mandatory structure "
        f"(P1/P2/P3 + sector context + action-plan table, sources per section)."
    )


async def _render_threat_brief(
    db: AsyncSession, scope: Scope, since: datetime, language: str = "fr",
) -> tuple[str, list[dict]]:
    """Call Anthropic Messages API with the ``web_search`` tool and return
    ``(brief_html, citations)``.

    ``citations`` is a list of ``{"title": str, "url": str}`` dicts collected
    from the model's ``server_tool_use`` and ``web_search_tool_result``
    blocks so the email can render a sources footer.

    Falls back to ``("", [])`` (caller renders a friendly "no brief"
    placeholder) when:

    * the active AI provider is not Anthropic (web_search is Anthropic-only)
    * no Anthropic API key is configured
    * the API call fails for any reason
    """
    # Import lazily so the digest module imports cleanly even when ai.py
    # has not been touched yet (unit tests).
    from src.routes.ai import _get_api_key, _runtime_provider_model, AI_PROVIDERS

    provider, model = await _runtime_provider_model(db)
    if provider != "anthropic":
        logger.info(
            "threat brief skipped — provider=%s does not support web_search",
            provider,
        )
        return "", []
    api_key = await _get_api_key("anthropic", db)
    if not api_key:
        logger.info("threat brief skipped — no Anthropic API key configured")
        return "", []

    window_days = int(getattr(scope, "threat_search_window_days", 7) or 7)
    prompt = (getattr(scope, "threat_prompt", "") or "").strip()
    if not prompt:
        return "", []

    endpoint = AI_PROVIDERS.get("anthropic", {}).get(
        "endpoint", "https://api.anthropic.com/v1/messages"
    )
    body = {
        "model": model,
        # 4096 was visibly cut off mid-table on multi-P1+P2+P3 briefs with
        # per-section sources. 16384 gives ample headroom for a verbose
        # triage + sector context + action plan; Sonnet 4.6 supports
        # significantly more if we ever need it.
        "max_tokens": 16384,
        "system": _threat_brief_system(language),
        "messages": [
            {"role": "user", "content": _threat_brief_user(prompt, window_days, language)},
        ],
        "tools": [
            {
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": 10,
            }
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                endpoint,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                json=body,
            )
    except httpx.RequestError as e:
        logger.warning("threat brief HTTP error: %s", e)
        return "", []
    if not resp.is_success:
        logger.warning(
            "threat brief HTTP %s — %s", resp.status_code, resp.text[:500]
        )
        return "", []

    data = resp.json()
    stop_reason = data.get("stop_reason")
    if stop_reason == "max_tokens":
        logger.warning(
            "threat brief hit max_tokens — output likely truncated "
            "(scope=%s, model=%s)",
            getattr(scope, "name", "?"), model,
        )
    text_parts: list[str] = []
    citations: list[dict] = []
    seen_urls: set[str] = set()
    for block in data.get("content", []) or []:
        btype = block.get("type")
        if btype == "text":
            text_parts.append(block.get("text", "") or "")
            # Per-paragraph citations attached to the text block.
            for cit in block.get("citations", []) or []:
                url = (cit.get("url") or "").strip()
                title = (cit.get("title") or url).strip()
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    citations.append({"title": title, "url": url})
        elif btype == "web_search_tool_result":
            for r in (block.get("content") or []):
                url = (r.get("url") or "").strip()
                title = (r.get("title") or url).strip()
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    citations.append({"title": title, "url": url})

    brief_html = _strip_llm_chatter("".join(text_parts))
    return brief_html, citations


def _render_threat_section(
    brief_html: str, citations: list[dict], language: str = "fr"
) -> str:
    """Wrap the Claude HTML brief into the digest section.

    The brief is expected to be a P1/P2/P3 triage with sources inlined at
    the end of each <h2> section (system prompt enforces this). The
    ``citations`` argument is kept for forensics / preview metadata but
    is no longer rendered as a footer — Claude's inline sources are the
    canonical placement so a reader sees the source next to the claim.
    """
    is_fr = (language or "fr").lower().startswith("fr")
    title = "Veille menaces" if is_fr else "Threat watch"
    no_brief = (
        "La veille menaces n'a pas pu être générée (clé Anthropic absente "
        "ou erreur API). Le contexte de veille reste enregistré pour le "
        "prochain envoi."
        if is_fr
        else "The threat brief could not be generated (missing Anthropic "
        "key or API error). The watch context is still saved for the "
        "next run."
    )

    if not brief_html.strip():
        body = (
            f'<div style="padding:14px;color:#7f8c8d;background:#fafafa;'
            f'border:1px dashed #ddd;border-radius:6px">{h_esc(no_brief)}</div>'
        )
    else:
        # The brief comes back as HTML from an LLM run with web search on, so
        # it is untrusted twice: the threat_prompt is written by a scope owner,
        # and a search result can carry an indirect injection. Trusting the
        # system prompt to forbid raw HTML — which is what the previous
        # six-literal replace amounted to — misses <img onerror=…> and
        # <svg onload=…> entirely, since neither looks like any of the banned
        # strings. Allow-list instead: everything not named is dropped.
        cleaned = sanitize_html(brief_html)
        body = (
            f'<div style="padding:14px 16px;background:#fff;border:1px solid #e0e0e0;'
            f'border-radius:8px;line-height:1.55;color:#2c3e50">{cleaned}</div>'
        )
    return (
        f'<h2 style="color:#2c3e50;border-bottom:2px solid #2c3e50;'
        f'padding-bottom:6px;margin-top:28px">{h_esc(title)}</h2>{body}'
    )


def render_threat_digest_html(
    scope_name: str,
    brief_html: str,
    citations: list[dict],
    user_name: str = "",
    since: datetime | None = None,
    language: str = "fr",
) -> str:
    """Threat-watch digest body (M22 — free-prompt brief).

    ``brief_html`` is the HTML produced by Claude with web_search; an
    empty string yields the "could not generate" placeholder.
    """
    intro = (
        f"Voici la <strong>veille menaces</strong> du périmètre "
        f"<strong>{h_esc(scope_name)}</strong> depuis le précédent digest "
        f"({h_esc(_since_txt(since))})."
    )
    section = _render_threat_section(brief_html, citations, language)
    return _wrap_html(_greeting(user_name), intro, section)


def render_html(
    scope_name: str,
    groups: list[AlertGroup],
    analyses: dict[uuid.UUID, AlertAnalysis],
    threat_brief_html: str = "",
    threat_citations: list[dict] | None = None,
    user_name: str = "",
    since: datetime | None = None,
    language: str = "fr",
) -> str:
    """Combined vuln + threat preview body.

    Kept for ``/api/digest/preview`` so a user can see both sections
    on one page. The two scheduled digests use
    :func:`render_vuln_digest_html` and :func:`render_threat_digest_html`
    directly so each email shows only its own section.
    """
    intro = (
        f"Aperçu du digest Watch du périmètre <strong>{h_esc(scope_name)}</strong>"
        f" — vulnérabilités critiques et menaces relevées depuis le précédent digest "
        f"({h_esc(_since_txt(since))})."
    )

    if groups:
        v_cards = "".join(
            _render_group_card(g, analyses.get(g.primary.id)) for g in groups
        )
        vuln_section = (
            f'<h2 style="color:#2c3e50;border-bottom:2px solid #c0392b;'
            f'padding-bottom:6px;margin-top:28px">'
            f'Vulnérabilités critiques ({len(groups)})</h2>{v_cards}'
        )
    else:
        vuln_section = (
            f'<h2 style="color:#2c3e50;border-bottom:2px solid #c0392b;'
            f'padding-bottom:6px;margin-top:28px">Vulnérabilités critiques</h2>'
            f'<div style="padding:14px;color:#7f8c8d;background:#fafafa;'
            f'border:1px dashed #ddd;border-radius:6px">'
            f'Aucune vulnérabilité critique n\'a été publiée dans votre périmètre depuis le précédent digest.'
            f'</div>'
        )

    threat_section = _render_threat_section(
        threat_brief_html, threat_citations or [], language
    )

    return _wrap_html(_greeting(user_name), intro, vuln_section + threat_section)


def _send_smtp(to: str, subject: str, html: str) -> tuple[bool, str]:
    """Return (ok, error_message). When SMTP isn't configured, returns
    (False, "smtp_not_configured") and the caller stamps the run as
    such — the row + HTML stays in the database for inspection.
    """
    return send_html_email(_smtp_settings(), to, subject, html)


async def _build_analyses(
    db: AsyncSession, groups: list[AlertGroup]
) -> dict[uuid.UUID, AlertAnalysis]:
    """Fetch-or-generate an :class:`AlertAnalysis` for each group primary.

    Calls run with bounded concurrency (semaphore) so a digest of 50+
    vulnerabilities completes in a few minutes instead of half an hour.
    The semaphore size is conservative (4) to stay well under Anthropic
    and OpenAI rate limits without burning through them when the digest
    fans out across many scopes in the same tick.

    Per-group failures are swallowed (logged) so one bad LLM call
    doesn't sink the whole digest — the card falls back to the raw
    summary for affected groups.
    """
    out: dict[uuid.UUID, AlertAnalysis] = {}
    if not groups:
        return out
    sem = asyncio.Semaphore(int(os.getenv("WATCH_ANALYSIS_CONCURRENCY", "4")))

    async def _one(g: AlertGroup) -> tuple[uuid.UUID, AlertAnalysis | None]:
        # Each task takes its own AsyncSession — SQLAlchemy's async session
        # is single-flight, so we can't share the caller's db across the
        # concurrent _one() coroutines without serialising on a lock.
        a = g.primary
        async with sem:
            try:
                async with async_session() as task_db:
                    row = await generate_or_get(
                        task_db, a, None, language=_DIGEST_LANGUAGE,
                    )
                    return a.id, row
            except Exception:
                logger.exception(
                    "analysis failed for %s:%s — falling back to raw summary",
                    a.source, a.external_id,
                )
                return a.id, None

    results = await asyncio.gather(*[_one(g) for g in groups])
    for alert_id, row in results:
        if row is not None:
            out[alert_id] = row
    return out


async def _collect_recipients(db: AsyncSession, scope: Scope) -> set[str]:
    """Owner email + every distinct ScopeRecipient address."""
    out: set[str] = set()
    owner = (await db.execute(
        select(User).where(User.id == scope.owner_id)
    )).scalar_one_or_none()
    if owner and owner.email:
        out.add(owner.email.lower())
    recipient_rows = (await db.execute(
        select(ScopeRecipient.email).where(ScopeRecipient.scope_id == scope.id)
    )).scalars().all()
    for e in recipient_rows:
        if e:
            out.add(e.lower())
    return out


async def _already_sent_today(
    db: AsyncSession, email: str, scope_id: uuid.UUID, kind: str, today: str
) -> bool:
    """True if this (recipient × scope × kind × day) has reached a
    terminal state (``sent`` or ``failed``).

    ``skipped_empty`` is intentionally NOT terminal: it means "we tried
    but had nothing to send" (e.g. the vuln window held no alerts, or
    Claude+web_search returned an empty brief). A later tick the same
    day should be allowed to re-evaluate and actually send. The partial
    unique index in migration 011 enforces the same rule at the DB level."""
    row = (await db.execute(
        select(DigestRun.id).where(and_(
            DigestRun.user_email == email,
            DigestRun.scope_id == scope_id,
            DigestRun.kind == kind,
            DigestRun.calendar_date == today,
            DigestRun.status.in_(("sent", "failed")),
        ))
    )).scalar_one_or_none()
    return row is not None


async def _stamp_skipped_empty(
    db: AsyncSession,
    email: str,
    scope_id: uuid.UUID,
    kind: str,
    today: str,
    now_utc: datetime,
) -> None:
    """Stamp a ``skipped_empty`` DigestRun, deduping if one already
    exists for the same (user × scope × kind × day).

    Since proposal-2 (migration 011), ``skipped_empty`` no longer
    participates in the unique constraint — without dedup, every
    scheduler tick that finds the scope empty would add a new row.
    We keep exactly one informational row per day."""
    existing = (await db.execute(
        select(DigestRun.id).where(and_(
            DigestRun.user_email == email,
            DigestRun.scope_id == scope_id,
            DigestRun.kind == kind,
            DigestRun.calendar_date == today,
            DigestRun.status == "skipped_empty",
        ))
    )).scalar_one_or_none()
    if existing is not None:
        return
    db.add(DigestRun(
        id=uuid.uuid4(),
        user_email=email,
        scope_id=scope_id,
        kind=kind,
        calendar_date=today,
        sent_at=now_utc,
        status="skipped_empty",
        alerts_count=0,
        error_message="",
    ))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()


async def _since_for(
    db: AsyncSession, email: str, scope_id: uuid.UUID, now_utc: datetime
) -> datetime:
    """Recipient-scope-wide since-window — shared by both digest kinds.

    The "last sent" window is intentionally NOT split by kind: when
    either digest gets sent, both windows advance. This matches what
    a recipient expects ("I just got an email, the next one starts
    from here") and avoids double-reporting the same article when the
    two cadences happen to align on the same day.
    """
    since = await _last_sent_at(db, email, scope_id)
    if since is None:
        since = now_utc - timedelta(days=_FIRST_RUN_LOOKBACK_DAYS)
    return since


async def _send_vuln_digest(
    db: AsyncSession,
    scope: Scope,
    email: str,
    today: str,
    now_utc: datetime,
) -> bool:
    """Build + send the vulnerability digest for one (scope, recipient).

    Returns True on actual SMTP send. Always stamps a ``DigestRun``
    row (sent / failed / skipped_empty) so the idempotency key
    blocks re-runs for the same calendar day.
    """
    recipient_user = (await db.execute(
        select(User).where(User.email == email)
    )).scalar_one_or_none()
    since = await _since_for(db, email, scope.id, now_utc)

    personalized = await _alerts_for_scope(db, recipient_user, scope, since)
    groups = group_alerts(personalized)
    if not groups:
        await _stamp_skipped_empty(db, email, scope.id, "vuln", today, now_utc)
        logger.info("vuln digest skipped (empty) for %s scope %s", email, scope.name)
        return False

    analyses = await _build_analyses(db, groups)
    display_name = recipient_user.name if recipient_user else ""
    html = render_vuln_digest_html(
        scope.name, groups, analyses,
        user_name=display_name or "", since=since,
    )
    n = len(groups)
    subj = f"[Watch] {scope.name} — {n} vuln. critique{'s' if n > 1 else ''}"
    ok, err = _send_smtp(email, subj, html)
    db.add(DigestRun(
        id=uuid.uuid4(),
        user_email=email,
        scope_id=scope.id,
        kind="vuln",
        calendar_date=today,
        sent_at=now_utc,
        status=("sent" if ok else "failed"),
        alerts_count=n,
        error_message=err or "",
        body_html=html,
    ))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return False
    if ok:
        logger.info(
            "vuln digest sent to %s scope %s (n=%s since=%s)",
            email, scope.name, n, since.isoformat(),
        )
    else:
        logger.info("vuln digest failed for %s scope %s: %s",
                    email, scope.name, err or "unknown")
    return ok


async def _send_threat_digest(
    db: AsyncSession,
    scope: Scope,
    email: str,
    today: str,
    now_utc: datetime,
) -> bool:
    """Build + send the threat-watch digest for one (scope, recipient).

    M22: free-prompt CISO context is handed to Claude (with the
    ``web_search`` tool) at send time. The HTML brief + source URLs
    returned by the model are pasted into the email. An empty
    ``Scope.threat_prompt`` is filtered upstream by :func:`_is_threat_due`,
    but we double-check here so a misconfigured caller can't fall
    through.

    Empty Anthropic key (or non-Anthropic provider) yields a brief
    with the "could not generate" placeholder — we still send so the
    recipient knows the cadence fired and can fix the AI config.
    """
    if not (getattr(scope, "threat_prompt", "") or "").strip():
        await _stamp_skipped_empty(db, email, scope.id, "threat", today, now_utc)
        logger.info(
            "threat digest skipped (empty prompt) for %s scope %s",
            email, scope.name,
        )
        return False

    recipient_user = (await db.execute(
        select(User).where(User.email == email)
    )).scalar_one_or_none()
    since = await _since_for(db, email, scope.id, now_utc)
    brief_html, citations = await _render_threat_brief(
        db, scope, since, language=_DIGEST_LANGUAGE,
    )

    display_name = recipient_user.name if recipient_user else ""
    html = render_threat_digest_html(
        scope.name, brief_html, citations,
        user_name=display_name or "", since=since,
        language=_DIGEST_LANGUAGE,
    )
    subj = f"[Watch] {scope.name} — Veille menaces"
    ok, err = _send_smtp(email, subj, html)
    db.add(DigestRun(
        id=uuid.uuid4(),
        user_email=email,
        scope_id=scope.id,
        kind="threat",
        calendar_date=today,
        sent_at=now_utc,
        status=("sent" if ok else "failed"),
        alerts_count=len(citations),
        error_message=err or "",
        body_html=html,
    ))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return False
    if ok:
        logger.info(
            "threat digest sent to %s scope %s (sources=%s since=%s)",
            email, scope.name, len(citations), since.isoformat(),
        )
    else:
        logger.info("threat digest failed for %s scope %s: %s",
                    email, scope.name, err or "unknown")
    return ok


async def tick_digests(db: AsyncSession) -> int:
    """Send any digests due in the current tick.

    Checks two independent cadences per scope:

    * **Vulnerability digest** — driven by ``digest_*`` columns
      (legacy). Stamped with ``DigestRun.kind='vuln'``.
    * **Threat-watch digest** (M18) — driven by ``threat_digest_*``
      columns (off/daily/weekly). Stamped with
      ``DigestRun.kind='threat'``.

    The two cadences are independent — a scope can send only vuln,
    only threat, both on the same day (subjects differ), or neither.
    Per-kind idempotency comes from the
    ``uq_digest_user_scope_kind_date`` unique constraint.

    Returns the count of actual SMTP sends across both kinds.
    """
    now_utc = datetime.now(timezone.utc)
    scopes = (await db.execute(select(Scope))).scalars().all()
    sent = 0
    for scope in scopes:
        vuln_due = _is_due(scope, now_utc)
        threat_due = _is_threat_due(scope, now_utc)
        if not vuln_due and not threat_due:
            continue

        recipients = await _collect_recipients(db, scope)
        if not recipients:
            continue

        # Compute "today" in each digest's own timezone — vuln and
        # threat may live in different TZs in theory, although the
        # scope UI normally keeps them aligned.
        if vuln_due:
            vuln_tz = _tz(scope.digest_timezone or "Europe/Paris")
            vuln_today = now_utc.astimezone(vuln_tz).strftime("%Y-%m-%d")
        if threat_due:
            threat_tz = _tz(scope.threat_digest_timezone or "Europe/Paris")
            threat_today = now_utc.astimezone(threat_tz).strftime("%Y-%m-%d")

        for email in recipients:
            if vuln_due and not await _already_sent_today(
                db, email, scope.id, "vuln", vuln_today
            ):
                if await _send_vuln_digest(db, scope, email, vuln_today, now_utc):
                    sent += 1
            if threat_due and not await _already_sent_today(
                db, email, scope.id, "threat", threat_today
            ):
                if await _send_threat_digest(db, scope, email, threat_today, now_utc):
                    sent += 1
    return sent


async def force_send_digest_for_scope(
    db: AsyncSession, scope: Scope, kind: str
) -> dict:
    """Force-send the requested digest kind to every recipient of ``scope``.

    Bypasses both the schedule (no need to wait for the next window)
    and the per-day idempotency (any existing terminal ``DigestRun`` row
    for today is deleted before re-render so the new send is recorded
    and the unique partial index is not violated). Used by the admin
    "Envoyer maintenant" button in the scope modal.

    Returns ``{"sent": int, "failed": int, "recipients": [emails...]}``.
    Raises ``ValueError`` on invalid ``kind`` or unconfigured scope so
    the caller can return a clean 4xx.
    """
    if kind not in ("vuln", "threat"):
        raise ValueError("kind must be 'vuln' or 'threat'")
    if kind == "threat" and not (getattr(scope, "threat_prompt", "") or "").strip():
        raise ValueError("scope has no threat_prompt configured")

    recipients = sorted(await _collect_recipients(db, scope))
    if not recipients:
        return {"sent": 0, "failed": 0, "recipients": []}

    now_utc = datetime.now(timezone.utc)
    tz_name = (
        scope.threat_digest_timezone if kind == "threat" else scope.digest_timezone
    ) or "Europe/Paris"
    today = now_utc.astimezone(_tz(tz_name)).strftime("%Y-%m-%d")

    # Wipe any terminal row for today so the new send is not blocked by
    # the partial unique index (uq_digest_user_scope_kind_date_sent) and
    # the row history shows the manual force-send instead of the stale one.
    await db.execute(
        delete(DigestRun).where(
            DigestRun.scope_id == scope.id,
            DigestRun.kind == kind,
            DigestRun.calendar_date == today,
            DigestRun.user_email.in_(recipients),
        )
    )
    await db.commit()

    sent = 0
    failed = 0
    sender = _send_vuln_digest if kind == "vuln" else _send_threat_digest
    for email in recipients:
        try:
            ok = await sender(db, scope, email, today, now_utc)
        except Exception:
            logger.exception(
                "force-send %s failed for %s scope %s", kind, email, scope.name
            )
            failed += 1
            continue
        if ok:
            sent += 1
        else:
            failed += 1
    return {"sent": sent, "failed": failed, "recipients": recipients}
