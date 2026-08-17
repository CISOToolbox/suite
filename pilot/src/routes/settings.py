"""Centralized settings: AI config, proxy, pushed to all modules."""

from __future__ import annotations

import os
import re

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.database import get_db
from src.models import AppSettings, ModuleRegistry, User
from src.settings_crypto import decrypt_setting, encrypt_setting, is_secret_key

router = APIRouter(prefix="/api/settings", tags=["settings"])

SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

# AWS region names end up inside the Bedrock hostname in every module
# (`https://bedrock-runtime.{region}.amazonaws.com`). Validate at the point
# where the value enters the suite, on top of the per-module check.
_BEDROCK_REGION_RE = re.compile(r"^[a-z0-9-]{1,32}$")

# Settings keys
SETTINGS_KEYS = [
    "ai_provider", "ai_model",
    "ai_key_anthropic", "ai_key_openai", "ai_key_gemini",
    "ai_key_bedrock", "ai_secret_bedrock", "ai_region_bedrock",
    "ai_custom_endpoint", "ai_custom_model", "ai_custom_key", "ai_custom_label",
    "http_proxy", "https_proxy", "no_proxy",
    # SMTP (used by Watch digest, future module notifications). Pushed to every
    # registered module via PUT /api/internal/smtp on save.
    "smtp_host", "smtp_port", "smtp_user", "smtp_password",
    "smtp_from", "smtp_tls",
    # Demo mode: when "false", connectors stop returning mock/demo values for
    # unconfigured providers (M365/AWS KPIs). Empty/anything else = on (default).
    "demo_mode",
]


async def _get_setting(key: str, db: AsyncSession) -> str:
    result = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = result.scalar_one_or_none()
    raw = (s.value if s else "") or ""
    # Rows written before encryption carry no marker and come back unchanged,
    # then get encrypted on their next write (see settings_crypto).
    return decrypt_setting(raw) if is_secret_key(key) else raw


async def _set_setting(key: str, value: str, db: AsyncSession) -> None:
    # Pilot held the SMTP password, the AI provider keys and the cloud
    # connector credentials in cleartext, and had no crypto module at all —
    # a stolen pg_dump handed them over as-is. Credentials are encrypted at
    # rest now; provider names, models and regions stay readable.
    if is_secret_key(key):
        value = encrypt_setting(value)
    result = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = result.scalar_one_or_none()
    if s:
        s.value = value
    else:
        db.add(AppSettings(key=key, value=value))


@router.get("")
async def get_settings(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    settings = {}
    for key in SETTINGS_KEYS:
        val = await _get_setting(key, db)
        # Mask secrets: API keys + Bedrock secret + SMTP password
        if ("key_" in key or "secret_" in key or key == "smtp_password") and val and len(val) > 4:
            settings[key] = "configured"
        else:
            settings[key] = val
    return settings


class SettingsUpdate(BaseModel):
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_key_anthropic: str | None = None
    ai_key_openai: str | None = None
    ai_key_gemini: str | None = None
    ai_key_bedrock: str | None = None
    ai_secret_bedrock: str | None = None
    ai_region_bedrock: str | None = None
    ai_custom_endpoint: str | None = None
    ai_custom_model: str | None = None
    ai_custom_key: str | None = None
    ai_custom_label: str | None = None
    http_proxy: str | None = None
    https_proxy: str | None = None
    no_proxy: str | None = None
    # SMTP (pushed to modules via /api/internal/smtp). smtp_password is masked
    # in GET; if the client re-sends the literal "configured" placeholder we
    # interpret it as "do not change" (handled in update_settings).
    smtp_host: str | None = None
    smtp_port: str | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_tls: str | None = None
    demo_mode: str | None = None


@router.put("")
async def update_settings(body: SettingsUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)

    # Validate AI keys before saving
    validation = {}
    if body.ai_region_bedrock is not None and body.ai_region_bedrock != "":
        # The region is interpolated into the Bedrock hostname by every
        # module; refuse anything that isn't a region name at the source.
        if not _BEDROCK_REGION_RE.fullmatch(body.ai_region_bedrock.strip()):
            raise HTTPException(status_code=400, detail="Region Bedrock invalide")
        body.ai_region_bedrock = body.ai_region_bedrock.strip()
    if body.ai_key_anthropic:
        valid, err = await _validate_ai_key("anthropic", body.ai_key_anthropic)
        validation["anthropic"] = {"valid": valid, "error": err}
        if not valid:
            raise HTTPException(status_code=400, detail=f"Cle Anthropic invalide: {err}")
    if body.ai_key_gemini:
        valid, err = await _validate_ai_key("gemini", body.ai_key_gemini)
        if not valid:
            raise HTTPException(status_code=422, detail=f"Clé Gemini invalide : {err}")
    if body.ai_key_openai:
        valid, err = await _validate_ai_key("openai", body.ai_key_openai)
        validation["openai"] = {"valid": valid, "error": err}
        if not valid:
            raise HTTPException(status_code=400, detail=f"Cle OpenAI invalide: {err}")
    if body.ai_custom_endpoint and body.ai_custom_model:
        # C-3 fix: validate endpoint URL to prevent SSRF
        _validate_endpoint_url(body.ai_custom_endpoint)
        valid, err = await _validate_ai_key("custom", body.ai_custom_key or "", body.ai_custom_endpoint, body.ai_custom_model)
        validation["custom"] = {"valid": valid, "error": err}
        if not valid:
            raise HTTPException(status_code=400, detail=f"LLM custom invalide: {err}")

    updates = body.model_dump(exclude_none=True)
    # If client re-sent the masked placeholder for smtp_password ("configured"),
    # preserve the stored value instead of overwriting it with the placeholder.
    if updates.get("smtp_password") == "configured":
        updates.pop("smtp_password")
    for key, value in updates.items():
        if key in SETTINGS_KEYS:
            await _set_setting(key, value, db)

    # When demo mode is turned off, clear the mock connector-KPI snapshots so the
    # simulated values stop showing on the dashboard (resolve_metric already
    # stops producing them). Real values, if credentials are set, repopulate on
    # the next connector run/scheduler pass.
    if updates.get("demo_mode") == "false":
        from sqlalchemy import delete as sa_delete
        from src.models import KpiDefinition, KpiSnapshot
        connector_ids = select(KpiDefinition.id).where(KpiDefinition.source_module == "connector")
        await db.execute(sa_delete(KpiSnapshot).where(KpiSnapshot.kpi_id.in_(connector_ids)))

    from src.audit import log_write
    changed = [k for k, v in body.model_dump().items() if v is not None]
    await log_write(db, user, None, "settings.update",
                    entity_type="settings", entity_id="pilot",
                    details={"fields": changed})  # names only — never values/keys
    await db.commit()

    # Push AI keys + proxy to all modules
    push_report = await _push_to_modules(db)

    return {"ok": True, "validation": validation, "push": push_report}


# Opt-out for a lab/on-prem LLM reachable only over plain HTTP. Off by
# default: this endpoint is called right after with the API key in an
# Authorization header (see _validate_ai_key), and the URL is then pushed
# to every module. Setting it to "true" accepts http:// — the key then
# travels in clear text, which is why it is an explicit, documented choice.
_ALLOW_INSECURE_LLM_ENDPOINT = os.getenv(
    "ALLOW_INSECURE_CUSTOM_LLM_ENDPOINT", "false"
).lower() in ("1", "true", "yes")


def _validate_endpoint_url(url: str) -> None:
    """Prevent SSRF: block private IPs, metadata endpoints, non-HTTPS.

    The previous version only inspected *IP literals* — a hostname landed
    in `except ValueError: pass` and was accepted, and http:// was allowed
    despite the docstring. It now resolves the name through the shared
    guard (same one the modules use on the custom-LLM branch), so a DNS
    name pointing at 127.0.0.1, a Docker sibling or the metadata service
    is refused, and https is required unless explicitly opted out of.
    """
    from src.ssrf_guard import resolve_safe_url
    try:
        resolve_safe_url(url, require_https=not _ALLOW_INSECURE_LLM_ENDPOINT)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Endpoint not allowed: {e}")


async def _validate_ai_key(provider: str, key: str, endpoint: str = "", model: str = "") -> tuple[bool, str]:
    """Test an AI API key with a minimal request."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if provider == "anthropic":
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"},
                    json={"model": "claude-sonnet-4-6", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
                )
                if resp.status_code in (401, 403):
                    return False, "Cle invalide ou expiree"
                return True, ""
            elif provider == "openai":
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
                    json={"model": "gpt-4o-mini", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
                )
                if resp.status_code in (401, 403):
                    return False, "Cle invalide ou expiree"
                return True, ""
            elif provider == "gemini":
                resp = await client.post(
                    "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent",
                    headers={"Content-Type": "application/json", "x-goog-api-key": key},
                    json={"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                          "generationConfig": {"maxOutputTokens": 1}},
                )
                if resp.status_code in (401, 403):
                    return False, "Cle invalide ou expiree"
                return True, ""
            elif provider == "custom":
                if not endpoint:
                    return False, "Endpoint requis"
                if not model:
                    return False, "Modele requis"
                url = endpoint.rstrip("/")
                if not url.endswith("/chat/completions"):
                    url += "/chat/completions"
                # Re-validate and pin: this request carries the API key in an
                # Authorization header, so it must reach the host that was
                # validated — not whatever the name resolves to a second later
                # (DNS rebinding). Redirects are not followed for the same
                # reason (httpx default).
                from src.ssrf_guard import resolve_safe_url
                try:
                    pinned_url, host_headers, extensions = resolve_safe_url(
                        url, require_https=not _ALLOW_INSECURE_LLM_ENDPOINT)
                except ValueError as e:
                    return False, f"Endpoint refuse: {e}"
                headers = {"Content-Type": "application/json", **host_headers}
                if key:
                    headers["Authorization"] = f"Bearer {key}"
                resp = await client.post(
                    pinned_url, headers=headers, extensions=extensions,
                    json={"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
                )
                if resp.status_code in (401, 403):
                    return False, "Cle invalide ou acces refuse"
                if resp.status_code >= 500:
                    return False, f"Serveur erreur {resp.status_code}"
                if resp.status_code == 404:
                    return False, f"Endpoint introuvable (404). Verifiez l'URL et le modele."
                return True, ""
    except httpx.ConnectError:
        return False, "Impossible de se connecter a l'endpoint"
    except httpx.RequestError:
        return False, "Erreur reseau lors de la validation"
    return False, "Fournisseur inconnu"


async def _push_to_modules(db: AsyncSession) -> dict:
    """Push AI keys and proxy config to all modules via their internal API."""
    result = await db.execute(select(ModuleRegistry))
    modules = result.scalars().all()

    # Gather settings to push
    ai_provider = await _get_setting("ai_provider", db)
    ai_model = await _get_setting("ai_model", db)
    ai_key_anthropic = await _get_setting("ai_key_anthropic", db)
    ai_key_openai = await _get_setting("ai_key_openai", db)
    ai_key_gemini = await _get_setting("ai_key_gemini", db)
    ai_key_bedrock = await _get_setting("ai_key_bedrock", db)
    ai_secret_bedrock = await _get_setting("ai_secret_bedrock", db)
    ai_region_bedrock = await _get_setting("ai_region_bedrock", db)
    ai_custom_endpoint = await _get_setting("ai_custom_endpoint", db)
    ai_custom_model = await _get_setting("ai_custom_model", db)
    ai_custom_key = await _get_setting("ai_custom_key", db)
    ai_custom_label = await _get_setting("ai_custom_label", db)
    http_proxy = await _get_setting("http_proxy", db)
    https_proxy = await _get_setting("https_proxy", db)
    no_proxy = await _get_setting("no_proxy", db)

    payload = {}
    if ai_key_anthropic:
        payload["anthropic"] = ai_key_anthropic
    if ai_key_openai:
        payload["openai"] = ai_key_openai
    if ai_key_gemini:
        payload["gemini"] = ai_key_gemini
    # Bedrock: access key id goes under "bedrock", secret + region as extras
    # (the module /api/ai/keys handler upserts ai_key_bedrock + ai_secret_bedrock
    # + ai_region_bedrock).
    if ai_key_bedrock:
        payload["bedrock"] = ai_key_bedrock
    if ai_secret_bedrock:
        payload["ai_secret_bedrock"] = ai_secret_bedrock
    if ai_region_bedrock:
        payload["ai_region_bedrock"] = ai_region_bedrock
    if ai_provider:
        payload["provider"] = ai_provider
    if ai_model:
        payload["model"] = ai_model

    proxy_payload = {}
    if http_proxy:
        proxy_payload["http_proxy"] = http_proxy
    if https_proxy:
        proxy_payload["https_proxy"] = https_proxy
    if no_proxy:
        proxy_payload["no_proxy"] = no_proxy

    # SMTP payload — only sent if host is set; password is sent in clear over
    # the internal-network channel (already protected by SERVICE_TOKEN + the
    # docker network being private). Modules cache it in memory only.
    smtp_host = await _get_setting("smtp_host", db)
    smtp_payload: dict = {}
    if smtp_host:
        smtp_payload = {
            "host": smtp_host,
            "port": await _get_setting("smtp_port", db),
            "user": await _get_setting("smtp_user", db),
            "password": await _get_setting("smtp_password", db),
            "from_addr": await _get_setting("smtp_from", db),
            "tls": await _get_setting("smtp_tls", db),
        }

    report = {}
    headers = {"X-Service-Token": SERVICE_TOKEN, "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for m in modules:
            if not m.internal_url:
                report[m.id] = "skipped"
                continue
            base = m.internal_url.rstrip("/")
            try:
                # Push AI keys
                if payload:
                    resp = await client.put(base + "/api/ai/keys", headers=headers, json=payload)
                    if not resp.is_success:
                        report[m.id] = f"ai_keys: HTTP {resp.status_code}"
                        continue

                # Push custom LLM config
                if ai_custom_endpoint:
                    custom_payload = {
                        "endpoint": ai_custom_endpoint,
                        "model": ai_custom_model,
                        "key": ai_custom_key,
                        "label": ai_custom_label or "Custom LLM",
                    }
                    resp = await client.put(base + "/api/internal/ai-custom", headers=headers, json=custom_payload)
                    # Ignore 404 if module doesn't support it yet

                # Push proxy config
                if proxy_payload:
                    resp = await client.put(base + "/api/internal/proxy", headers=headers, json=proxy_payload)

                # Push SMTP config (only modules that opted in via the route
                # will accept it; 404 is silently ignored).
                if smtp_payload:
                    try:
                        await client.put(base + "/api/internal/smtp", headers=headers, json=smtp_payload)
                    except httpx.HTTPError:
                        pass

                # Push centralised connector credentials. Re-discovers
                # consumers each pass via GET /api/connectors so new
                # modules joining the suite get seeded with whatever
                # connector creds Pilot already has. Modules without
                # the connectors framework (older builds) 404 — we
                # skip them silently. See docs/CHANTIER_CONNECTEURS.md.
                await _push_connectors_to(client, base, headers, db)

                report[m.id] = "ok"
            except Exception as e:
                report[m.id] = f"error: {str(e)[:50]}"

    return report


# ── Connectors push helper (CHANTIER_CONNECTEURS étape 7) ──────────


_CONNECTOR_FIELD_PREFIX = "connector_"


async def _list_configured_connectors(db: AsyncSession) -> dict[str, dict[str, str]]:
    """Group every ``connector_<id>_<field>`` AppSettings row into
    ``{connector_id: {field_id: value}}``. Only non-empty values are
    returned — Pilot does not push empty fields (it would clear a value
    on the target module)."""
    rows = await db.execute(
        select(AppSettings).where(AppSettings.key.like(f"{_CONNECTOR_FIELD_PREFIX}%"))
    )
    out: dict[str, dict[str, str]] = {}
    for row in rows.scalars().all():
        if not row.value:
            continue
        remainder = row.key[len(_CONNECTOR_FIELD_PREFIX):]
        # Split on the FIRST underscore: connector_id may contain its own
        # underscores (none today, but futureproof for "m365_gov" etc.)
        # — match against the registered ids instead.
        # Simpler convention: connector_id is always a single token, so
        # split on the first underscore.
        if "_" not in remainder:
            continue
        cid, field_id = remainder.split("_", 1)
        # Decrypt before pushing: these values go out to the modules over the
        # service-token channel, which expects the credential itself. Storing
        # them encrypted must not turn into shipping ciphertext downstream.
        value = decrypt_setting(row.value) if is_secret_key(row.key) else row.value
        if not value:
            continue
        out.setdefault(cid, {})[field_id] = value
    return out


async def _push_connectors_to(
    client: httpx.AsyncClient,
    base: str,
    headers: dict,
    db: AsyncSession,
) -> None:
    """Seed a single module with every connector cred Pilot has on file.

    Strategy:
      1. Ask the module what connectors it declares via
         GET /api/connectors. 404 → module pre-dates the framework,
         skip silently.
      2. For each declared connector that Pilot also has creds for, PUT
         them via /api/internal/connectors/{id}. Any 4xx is logged but
         not fatal — a misconfigured connector type shouldn't sink the
         whole settings push.
    """
    try:
        resp = await client.get(base + "/api/connectors", headers=headers)
    except httpx.RequestError:
        return
    if resp.status_code == 404:
        return
    if not resp.is_success:
        return
    try:
        declared = {c.get("id") for c in (resp.json() or {}).get("connectors", []) if c.get("id")}
    except ValueError:
        return
    if not declared:
        return
    available = await _list_configured_connectors(db)
    for cid in declared & available.keys():
        try:
            await client.put(
                f"{base}/api/internal/connectors/{cid}",
                headers=headers,
                json=available[cid],
            )
        except httpx.HTTPError:
            # Per-connector failure is non-fatal — the rest of the push
            # continues. The aggregator's PUT path retries on user write.
            pass
