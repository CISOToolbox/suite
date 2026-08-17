"""LLM analysis service for alerts (Phase 4).

Produces an 8-section JSON analysis of an Alert, cached on
:class:`AlertAnalysis` by a sha256 hash of the alert fields that
materially affect the prompt. Subsequent calls against an unchanged
alert return the cached row without re-billing the LLM provider.

The prompt is intentionally terse and asks the model to return a
strict JSON envelope so we don't have to parse free-form Markdown.
A parsing failure falls back to wrapping the raw text in
``{"executive_summary": "<text>", ...empty...}`` so the user still
gets *something* useful.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Alert, AlertAnalysis, User
from src.routes.ai import call_llm_text, _runtime_provider_model

logger = logging.getLogger("watch-analysis")

SECTION_KEYS = [
    "executive_summary",
    "technical_detail",
    "exploitation_status",
    "affected_components",
    "business_impact",
    "recommended_actions",
    "references_curated",
    "confidence",
]

_SYSTEM_PROMPT_EN = """You are a senior security analyst writing concise triage briefs for a CISO.
You receive a single vulnerability advisory and return a STRICT JSON object
with these keys (string values, plain text — no markdown):

  - executive_summary    : 2-3 sentences. What it is, why it matters, how urgent.
  - technical_detail     : 3-5 sentences. Attack vector, complexity, vulnerable component.
  - exploitation_status  : 1-2 sentences. KEV? PoC public? Active exploitation? Unknown OK.
  - affected_components  : 1-3 sentences. Vendor/product/version range.
  - business_impact      : 2-3 sentences. Concrete consequences if exploited.
  - recommended_actions  : 3-5 short bullets joined by " | " (no bullets characters).
  - references_curated   : the most useful 1-3 URLs joined by " | ". Pick from the advisory's references.
  - confidence           : exactly one of: "high", "medium", "low".

Return ONLY the JSON object, no preamble, no code fences.
If a field is genuinely unknowable from the advisory, return the string "unknown".
"""

_SYSTEM_PROMPT_FR = """Tu es analyste cybersécurité senior et tu rédiges des fiches de triage
concises pour un RSSI. Tu reçois un avis de vulnérabilité et tu réponds par un
objet JSON STRICT contenant ces clés (valeurs en texte simple, pas de markdown) :

  - executive_summary    : 2-3 phrases. Ce que c'est, pourquoi ça compte, quel niveau d'urgence.
  - technical_detail     : 3-5 phrases. Vecteur d'attaque, complexité, composant vulnérable.
  - exploitation_status  : 1-2 phrases. KEV ? PoC public ? Exploitation active ? "inconnu" admis.
  - affected_components  : 1-3 phrases. Éditeur / produit / plage de versions affectées.
  - business_impact      : 2-3 phrases. Conséquences concrètes en cas d'exploitation.
  - recommended_actions  : 3-5 actions courtes jointes par " | " (sans tirets ni puces).
  - references_curated   : 1-3 URLs les plus utiles jointes par " | " (puisées dans les références).
  - confidence           : exactement l'une de : "high", "medium", "low".

Réponds UNIQUEMENT par l'objet JSON, sans préambule ni balises de code.
Si une rubrique est réellement inconnue à partir de l'avis, retourne la chaîne "unknown".
Les clés JSON restent en anglais (executive_summary…) — seules les valeurs sont en français.
"""


def _system_prompt(language: str) -> str:
    return _SYSTEM_PROMPT_FR if (language or "en").lower().startswith("fr") else _SYSTEM_PROMPT_EN


def compute_alert_hash(alert: Alert) -> str:
    """sha256 of the fields that change the LLM output."""
    fields = "|".join([
        alert.source or "",
        alert.external_id or "",
        alert.title or "",
        alert.summary or "",
        alert.severity or "",
        str(alert.cvss_score or ""),
        str(alert.kev_listed or False),
        (alert.modified_at.isoformat() if alert.modified_at else ""),
        json.dumps(alert.affected_json or [], sort_keys=True, default=str),
        json.dumps(alert.references_json or [], sort_keys=True, default=str),
    ])
    return hashlib.sha256(fields.encode("utf-8")).hexdigest()


def _build_user_prompt(alert: Alert) -> str:
    return json.dumps({
        "source": alert.source,
        "id": alert.external_id,
        "title": alert.title,
        "summary": (alert.summary or "")[:6000],
        "severity": alert.severity,
        "cvss_score": alert.cvss_score,
        "cvss_vector": alert.cvss_vector,
        "epss_score": alert.epss_score,
        "kev_listed": alert.kev_listed,
        "affected": (alert.affected_json or [])[:20],
        "references": (alert.references_json or [])[:20],
    }, default=str, indent=2)


def _parse_sections(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        # Strip optional ```json fences the model sometimes leaves in.
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"executive_summary": text[:2000], **{k: "" for k in SECTION_KEYS if k != "executive_summary"}}
    out = {}
    for k in SECTION_KEYS:
        v = data.get(k)
        if isinstance(v, list):
            v = " | ".join(str(x) for x in v if x)
        out[k] = str(v) if v is not None else ""
    return out


async def generate_or_get(
    db: AsyncSession,
    alert: Alert,
    user: User | None,
    force: bool = False,
    language: str = "en",
) -> AlertAnalysis:
    """Return the cached analysis row for ``alert``, generating it via
    the LLM if missing or stale.

    ``language`` selects the locale of the LLM output (currently 'en'
    and 'fr'). Cache key is (alert_id, content_hash, language) so the
    same alert can carry one row per language. Unknown locales fall
    back to English silently.

    Setting ``force=True`` always re-generates (used by the "refresh"
    button in the UI and the digest pipeline when an analysis is older
    than the threshold).
    """
    lang = (language or "en").lower()
    if not lang.startswith(("en", "fr")):
        lang = "en"
    lang = "fr" if lang.startswith("fr") else "en"

    h = compute_alert_hash(alert)
    if not force:
        cached = (await db.execute(
            select(AlertAnalysis).where(
                AlertAnalysis.alert_id == alert.id,
                AlertAnalysis.content_hash == h,
                AlertAnalysis.language == lang,
            )
        )).scalar_one_or_none()
        if cached:
            return cached

    provider, model = await _runtime_provider_model(db)
    text = await call_llm_text(
        db,
        system=_system_prompt(lang),
        user_prompt=_build_user_prompt(alert),
        provider=provider,
        model=model,
        max_tokens=2000,
        timeout=120.0,
    )
    sections = _parse_sections(text)

    row = AlertAnalysis(
        id=uuid.uuid4(),
        alert_id=alert.id,
        content_hash=h,
        language=lang,
        sections=sections,
        provider=provider,
        model=model,
        generated_by_user_id=user.id if user else None,
        generated_at=datetime.now(timezone.utc),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    logger.info("analysis generated for %s:%s (%s/%s)",
                alert.source, alert.external_id, provider, lang)
    return row
