from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import re
import time
from typing import Optional

import httpx
from fastapi import APIRouter, Request, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import auth_enabled, get_current_user, require_admin
from src.database import get_db
from src.models import AppSettings, User
from src.schemas import AICompleteRequest, AICompleteResponse, AIConfigResponse, AIRuntimeResponse
from src.ai_models_common import AI_PROVIDERS
from src.settings_crypto import decrypt_setting, encrypt_setting_or_plain, is_secret_key

router = APIRouter(prefix="/api/ai", tags=["ai"])



async def _get_custom_llm(db):
    # Custom LLM provisioning comes from the suite-integration `internal`
    # router when deployed as part of the CISO Toolbox suite. In standalone
    # deployments that file is absent — fall back to the module's own
    # AppSettings (custom LLM configured via PUT /api/ai/keys).
    try:
        from src.routes.internal import _custom_llm
        cl = dict(_custom_llm)
    except ImportError:
        cl = {}
    if not cl.get("endpoint"):
        ep = await _get_setting("ai_custom_endpoint", db)
        if ep:
            cl = {
                "endpoint": ep,
                "key": await _get_setting("ai_custom_key", db),
                "model": await _get_setting("ai_custom_model", db),
                "label": "Custom LLM",
            }
    return cl


async def _get_api_key(provider: str, db: AsyncSession) -> str | None:
    key_name = f"ai_key_{provider}"
    result = await db.execute(select(AppSettings).where(AppSettings.key == key_name))
    setting = result.scalar_one_or_none()
    if setting and setting.value:
        # Cleartext rows written before encryption pass through unchanged.
        return decrypt_setting(setting.value)
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY")
    if provider == "gemini":
        return os.getenv("GEMINI_API_KEY")
    return None


async def _get_setting(key: str, db: AsyncSession) -> str:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    raw = (s.value if s and s.value else "") or ""
    return decrypt_setting(raw) if raw and is_secret_key(key) else raw


# An AWS region name is interpolated straight into the Bedrock hostname.
# Unvalidated, a "region" of `x.attacker.com/` turns
# https://bedrock-runtime.{region}.amazonaws.com/... into a request to the
# attacker's host — carrying the SigV4 signature and the AWS access key id.
_BEDROCK_REGION_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def _safe_bedrock_region(region: str) -> str:
    """Return `region` if it is a plausible AWS region name, else 400."""
    region = (region or "").strip()
    if not _BEDROCK_REGION_RE.fullmatch(region):
        raise HTTPException(status_code=400, detail="Invalid Bedrock region configured")
    return region


def _sign_v4(method, url, body, access_key, secret_key, region, service):
    """Minimal AWS Signature V4 -- ported from ai_common.js (_signV4)."""
    from urllib.parse import urlparse
    u = urlparse(url)
    date_stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    short_date = date_stamp[:8]
    payload_hash = hashlib.sha256((body or "").encode()).hexdigest()
    headers = {
        "host": u.netloc,
        "x-amz-date": date_stamp,
        "x-amz-content-sha256": payload_hash,
        "content-type": "application/json",
    }
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    canonical_request = "\n".join([
        method, u.path or "/", u.query, canonical_headers, signed_headers, payload_hash,
    ])
    credential_scope = f"{short_date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", date_stamp, credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_signing = _h(_h(_h(_h(("AWS4" + secret_key).encode(), short_date), region), service), "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


_ai_rate: dict[str, list[float]] = {}
AI_RATE_LIMIT = 20


def _check_rate_limit(user_id: str) -> None:
    now = time.time()
    times = _ai_rate.get(user_id, [])
    times = [t for t in times if now - t < 60]
    if len(times) >= AI_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (max 20/min)")
    times.append(now)
    _ai_rate[user_id] = times


def _check_ai_access(user: Optional[User]) -> None:
    if not auth_enabled() or user is None:
        return
    if user.role == "admin":
        return
    if user.ai_enabled != "true":
        raise HTTPException(status_code=403, detail="AI access not granted. Contact your administrator.")


async def call_llm_text(
    db: AsyncSession,
    system: str,
    user_prompt: str,
    provider: str | None = None,
    model: str | None = None,
    max_tokens: int = 4096,
    timeout: float = 120.0,
) -> str:
    """Server-initiated LLM call shared with phase-4 analysis.

    Uses the same provider/key resolution as ai_complete but skips the
    per-user rate limit + ai_enabled check (callers are trusted server
    code, not arbitrary clients).
    """
    if not provider or not model:
        rp, rm = await _runtime_provider_model(db)
        provider = provider or rp
        model = model or rm
    api_key = await _get_api_key(provider, db)
    if not api_key and provider != "custom":
        raise HTTPException(status_code=503, detail=f"API key not configured for provider: {provider}")
    provider_conf = AI_PROVIDERS.get(provider)
    if provider != "custom" and not provider_conf:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    # follow_redirects=False is httpx's default, stated here because the
    # custom-provider branch connects to a pinned IP: a redirect is a new
    # URL that never went through the guard.
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        try:
            if provider == "anthropic":
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": model,
                        "max_tokens": max_tokens,
                        "system": system,
                        "messages": [{"role": "user", "content": user_prompt}],
                    },
                )
            elif provider == "custom":
                custom = await _get_custom_llm(db)
                if not custom.get("endpoint"):
                    raise HTTPException(status_code=503, detail="Custom LLM not configured")
                url = custom["endpoint"].rstrip("/")
                if not url.endswith("/chat/completions"):
                    url += "/chat/completions"
                # SSRF guard: this POST carries the API key. Validating the
                # hostname and then handing the *name* to httpx left a
                # rebinding window — httpx re-resolves, so the vetted IP need
                # not be the one connected to. Connect to the pinned IP, and
                # keep the Host header + SNI so TLS still verifies the name.
                from src.ssrf_guard import resolve_safe_url
                try:
                    url, _host_headers, _ext = resolve_safe_url(url, require_https=True)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Custom LLM endpoint blocked: {e}")
                hdrs = {"Content-Type": "application/json", **_host_headers}
                if custom.get("key"):
                    hdrs["Authorization"] = f"Bearer {custom['key']}"
                resp = await client.post(url, headers=hdrs, extensions=_ext, json={
                    "model": custom.get("model") or model,
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_prompt},
                    ],
                })
            elif provider == "gemini":
                from urllib.parse import quote
                g_url = provider_conf["endpoint"].format(model=quote(model, safe=""))
                resp = await client.post(
                    g_url,
                    headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
                    json={
                        "systemInstruction": {"parts": [{"text": system}]},
                        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                        "generationConfig": {"maxOutputTokens": max_tokens},
                    },
                )
            elif provider == "bedrock":
                region = _safe_bedrock_region(
                    await _get_setting("ai_region_bedrock", db) or "us-east-1")
                secret = await _get_setting("ai_secret_bedrock", db)
                if not secret:
                    raise HTTPException(status_code=503, detail="Bedrock secret key / region not configured")
                from urllib.parse import quote
                b_url = f"https://bedrock-runtime.{region}.amazonaws.com/model/{quote(model, safe='')}/invoke"
                b_body = json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user_prompt}],
                })
                sig_headers = _sign_v4("POST", b_url, b_body, api_key, secret, region, "bedrock")
                resp = await client.post(b_url, headers=sig_headers, content=b_body)
            else:
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
                    json={
                        "model": model, "max_tokens": max_tokens,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user_prompt},
                        ],
                    },
                )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="AI provider timeout")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"AI provider error: {e}")

    if resp.status_code in (401, 403):
        raise HTTPException(status_code=503, detail="Invalid API key configured on server")
    if not resp.is_success:
        raise HTTPException(status_code=502, detail=f"AI provider returned error {resp.status_code}")
    data = resp.json()
    if provider == "gemini":
        parts = (data.get("candidates", [{}])[0].get("content", {}) or {}).get("parts", [])
        return "".join(pt.get("text", "") for pt in parts)
    if provider in ("anthropic", "bedrock"):
        return data.get("content", [{}])[0].get("text", "") or ""
    return data.get("choices", [{}])[0].get("message", {}).get("content", "") or ""


@router.post("/complete", response_model=AICompleteResponse)
async def ai_complete(body: AICompleteRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    api_key = await _get_api_key(body.provider, db)
    if not api_key:
        raise HTTPException(status_code=503, detail=f"API key not configured for provider: {body.provider}")

    provider_conf = AI_PROVIDERS.get(body.provider)
    if not provider_conf:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {body.provider}")

    # follow_redirects=False is httpx's default, stated here because the
    # custom-provider branch connects to a pinned IP: a redirect is a new
    # URL that never went through the guard.
    async with httpx.AsyncClient(timeout=170.0, follow_redirects=False) as client:
        try:
            if body.provider == "anthropic":
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": body.model,
                        "max_tokens": 4096,
                        "system": body.system,
                        "messages": [{"role": "user", "content": body.user}],
                    },
                )
            elif body.provider == "gemini":
                from urllib.parse import quote
                resp = await client.post(
                    provider_conf["endpoint"].format(model=quote(body.model, safe="")),
                    headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
                    json={
                        "systemInstruction": {"parts": [{"text": body.system}]},
                        "contents": [{"role": "user", "parts": [{"text": body.user}]}],
                        "generationConfig": {"maxOutputTokens": 4096},
                    },
                )
            elif body.provider == "custom":
                custom = await _get_custom_llm(db)
                if not custom.get("endpoint"):
                    raise HTTPException(status_code=503, detail="Custom LLM not configured")
                url = custom["endpoint"].rstrip("/")
                if not url.endswith("/chat/completions"):
                    url += "/chat/completions"
                # SSRF guard: this POST carries the API key. Validating the
                # hostname and then handing the *name* to httpx left a
                # rebinding window — httpx re-resolves, so the vetted IP need
                # not be the one connected to. Connect to the pinned IP, and
                # keep the Host header + SNI so TLS still verifies the name.
                from src.ssrf_guard import resolve_safe_url
                try:
                    url, _host_headers, _ext = resolve_safe_url(url, require_https=True)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Custom LLM endpoint blocked: {e}")
                hdrs = {"Content-Type": "application/json", **_host_headers}
                if custom.get("key"):
                    hdrs["Authorization"] = f"Bearer {custom['key']}"
                resp = await client.post(
                    url, headers=hdrs, extensions=_ext,
                    json={
                        "model": custom.get("model") or body.model,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "system", "content": body.system},
                            {"role": "user", "content": body.user},
                        ],
                    },
                )
            elif body.provider == "bedrock":
                region = _safe_bedrock_region(
                    await _get_setting("ai_region_bedrock", db) or "us-east-1")
                secret = await _get_setting("ai_secret_bedrock", db)
                if not secret:
                    raise HTTPException(status_code=503, detail="Bedrock secret key / region not configured")
                from urllib.parse import quote
                b_url = f"https://bedrock-runtime.{region}.amazonaws.com/model/{quote(body.model, safe='')}/invoke"
                b_body = json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4096,
                    "system": body.system,
                    "messages": [{"role": "user", "content": body.user}],
                })
                sig_headers = _sign_v4("POST", b_url, b_body, api_key, secret, region, "bedrock")
                resp = await client.post(b_url, headers=sig_headers, content=b_body)
            else:
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                    json={
                        "model": body.model,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "system", "content": body.system},
                            {"role": "user", "content": body.user},
                        ],
                    },
                )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="AI provider timeout")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"AI provider error: {e}")

    if resp.status_code in (401, 403):
        raise HTTPException(status_code=503, detail="Invalid API key configured on server")
    if not resp.is_success:
        raise HTTPException(status_code=502, detail=f"AI provider returned error {resp.status_code}")

    data = resp.json()

    if body.provider in ("anthropic", "bedrock"):
        text = data.get("content", [{}])[0].get("text", "")
    elif body.provider == "gemini":
        _parts = (data.get("candidates", [{}])[0].get("content", {}) or {}).get("parts", [])
        text = "".join(pt.get("text", "") for pt in _parts)
    else:
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")

    return AICompleteResponse(text=text)


def _ai_managed() -> bool:
    return os.getenv("AI_MANAGED_BY_PILOT", "false").lower() in ("1", "true", "yes")


async def _runtime_provider_model(db: AsyncSession) -> tuple[str, str]:
    async def _get(key: str) -> str:
        r = await db.execute(select(AppSettings).where(AppSettings.key == key))
        s = r.scalar_one_or_none()
        return (s.value if s and s.value else "") or ""
    provider = await _get("ai_provider") or "anthropic"
    model = await _get("ai_model") or AI_PROVIDERS.get(provider, AI_PROVIDERS["anthropic"])["defaultModel"]
    return provider, model


@router.get("/runtime", response_model=AIRuntimeResponse)
async def get_ai_runtime(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    managed = _ai_managed()
    if not auth_enabled() or user is None:
        can_use = True
    else:
        can_use = (user.role == "admin") or (user.ai_enabled == "true")
    provider, model = await _runtime_provider_model(db)
    try:
        custom = await _get_custom_llm(db)
        custom_configured = bool(custom.get("endpoint"))
    except Exception:
        custom_configured = False
    return AIRuntimeResponse(
        managed=managed,
        can_use=can_use,
        provider=provider,
        model=model,
        anthropic_configured=bool(await _get_api_key("anthropic", db)),
        openai_configured=bool(await _get_api_key("openai", db)),
        gemini_configured=bool(await _get_api_key("gemini", db)),
        custom_configured=custom_configured,
    )


@router.get("/config", response_model=AIConfigResponse)
async def get_ai_config(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    custom = await _get_custom_llm(db)
    providers = dict(AI_PROVIDERS)
    if custom.get("endpoint"):
        providers["custom"] = {
            "label": custom.get("label", "Custom LLM"),
            "models": [{"id": custom.get("model", "custom"), "label": custom.get("model", "Custom")}],
            "defaultModel": custom.get("model", "custom"),
            "endpoint": custom["endpoint"],
        }
    return AIConfigResponse(
        anthropic_configured=bool(await _get_api_key("anthropic", db)),
        openai_configured=bool(await _get_api_key("openai", db)),
        gemini_configured=bool(await _get_api_key("gemini", db)),
        providers=providers,
    )


@router.put("/keys")
async def set_ai_keys(body: dict, request: Request, db: AsyncSession = Depends(get_db)):
    """Set API keys. Authorized via service token (from Pilot) or admin user."""
    service_token = request.headers.get("X-Service-Token", "")
    import secrets as _secrets
    _expected_token = os.getenv("SERVICE_TOKEN", "")
    if not (service_token and _expected_token and _secrets.compare_digest(service_token, _expected_token)):
        try:
            user = await get_current_user(request, db)
        except HTTPException:
            raise HTTPException(status_code=401, detail="Not authenticated")
        require_admin(user)
    async def _upsert(key: str, value: str) -> None:
        # Encrypt credentials at rest, like every other module does through
        # shared/python/ai_proxy_common.py. Watch carries its own copy of this
        # route and stored the provider keys in cleartext: a stolen pg_dump
        # handed them over as-is.
        if value and is_secret_key(key):
            value = encrypt_setting_or_plain(value)
        r = await db.execute(select(AppSettings).where(AppSettings.key == key))
        s = r.scalar_one_or_none()
        if s:
            s.value = value
        else:
            db.add(AppSettings(key=key, value=value))
    for provider in ("anthropic", "openai", "bedrock", "gemini"):
        if provider in body:
            await _upsert(f"ai_key_{provider}", body.get(provider, ""))
    # Bedrock secret/region + custom-LLM config (standalone deployments)
    for extra in ("ai_secret_bedrock", "ai_region_bedrock",
                  "ai_custom_endpoint", "ai_custom_key", "ai_custom_model"):
        if extra in body:
            await _upsert(extra, body.get(extra, ""))
    if "provider" in body:
        await _upsert("ai_provider", body.get("provider", ""))
    if "model" in body:
        await _upsert("ai_model", body.get("model", ""))
    # LLM credential/config change — journaled with key-set FLAGS only (FEAT-30).
    from src.audit_common import log_write
    await log_write(db, None, request, "ai.keys_updated",
                    actor="pilot" if service_token else "",
                    entity_type="settings", entity_id="ai",
                    details={k: bool(body.get(k)) for k in body.keys() if k != "model"})
    await db.commit()
    return {"ok": True}


@router.get("/keys")
async def get_ai_keys(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    result = {}
    for provider in ("anthropic", "openai", "gemini"):
        key = await _get_api_key(provider, db)
        result[provider] = "configured" if key else ""
    return result



@router.post("/validate-key")
async def validate_key(provider: str = "anthropic", user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    api_key = await _get_api_key(provider, db)
    if not api_key:
        return {"valid": False, "error": "No API key configured"}

    provider_conf = AI_PROVIDERS.get(provider)
    if not provider_conf:
        return {"valid": False, "error": "Unknown provider"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if provider == "anthropic":
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": provider_conf["defaultModel"],
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            elif provider == "gemini":
                from urllib.parse import quote
                resp = await client.post(
                    provider_conf["endpoint"].format(
                        model=quote(provider_conf["defaultModel"], safe="")),
                    headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
                    json={
                        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                        "generationConfig": {"maxOutputTokens": 1},
                    },
                )
            else:
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                    json={
                        "model": provider_conf["defaultModel"],
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            valid = resp.status_code not in (401, 403)
            return {"valid": valid}
        except Exception as e:
            return {"valid": False, "error": str(e)}
