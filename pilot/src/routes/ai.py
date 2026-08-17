"""Pilot AI routes — intentionally NOT migrated to the shared ai_proxy_common.

The AI-proxy factorization (shared/python/ai_proxy_common.py + make_ai_router())
covers the eight *consumer* modules. Pilot is the AI *hub/manager* and keeps
its own purpose-built routes because its surface is deliberately different:

  - it exposes only POST /complete + GET /config (no /runtime, /keys,
    /validate-key — Pilot owns key management and pushes keys to the modules
    via /api/internal/ai-custom, so it does not serve those to itself);
  - its /complete has no "custom" provider branch and requires a key for every
    provider (the managed-mode hub only relays anthropic/openai/bedrock);
  - it lacks the schema (AIRuntimeResponse) and infra (_custom_llm,
    routes/internal) that the shared proxy assumes.

Forcing Pilot onto make_ai_router() would either weaken the shared master
(optional imports) or graft dead endpoints onto the hub. The pure helpers below
are identical to the shared ones — a future change could share them if the
master's schema imports were deferred, but that churn isn't worth ~100 lines.
"""
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
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import auth_enabled, get_current_user
from src.database import get_db
from src.models import AppSettings, User
from src.schemas import AICompleteRequest, AICompleteResponse, AIConfigResponse
from src.ai_models_common import AI_PROVIDERS
from src.settings_crypto import decrypt_setting, is_secret_key

router = APIRouter(prefix="/api/ai", tags=["ai"])



async def _get_setting(key: str, db: AsyncSession) -> str:
    """Read a setting, decrypting it when it is a secret.

    `_set_setting` (routes/settings.py) encrypts every key `is_secret_key()`
    recognises. Reading the column raw therefore hands the CIPHERTEXT to the
    provider, which answers 401 — surfaced here as 503 "Invalid API key
    configured on server", i.e. an accusation against a key that is perfectly
    valid. The shared master used by the modules
    (`shared/python/ai_proxy_common.py`) has always decrypted; Pilot keeps its
    own copy of this route and never got the fix.
    """
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
    """Minimal AWS Signature V4 — ported from ai_common.js (_signV4)."""
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


# Output cap sent to every provider. 4096 was too small for the grouping
# assistants: the reply came back truncated and the UI blamed the model.
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "8192"))


def _hit_output_cap(provider: str, data: dict) -> bool:
    """Did the provider stop because it ran out of output budget?

    Each vendor names it differently, and all three answer HTTP 200 while
    doing it — the truncation is only visible in this field.
    """
    if provider in ("anthropic", "bedrock"):
        return data.get("stop_reason") == "max_tokens"
    if provider == "gemini":
        cands = data.get("candidates") or [{}]
        return (cands[0] or {}).get("finishReason") == "MAX_TOKENS"
    choices = data.get("choices") or [{}]
    return (choices[0] or {}).get("finish_reason") == "length"


async def _get_api_key(provider: str, db: AsyncSession) -> str | None:
    key_name = f"ai_key_{provider}"
    result = await db.execute(select(AppSettings).where(AppSettings.key == key_name))
    setting = result.scalar_one_or_none()
    if setting and setting.value:
        # Encrypted at rest by _set_setting — see _get_setting above.
        return decrypt_setting(setting.value)
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY")
    return None


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

    async with httpx.AsyncClient(timeout=170.0) as client:
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
                        "max_tokens": AI_MAX_TOKENS,
                        "system": body.system,
                        "messages": [{"role": "user", "content": body.user}],
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
                    "max_tokens": AI_MAX_TOKENS,
                    "system": body.system,
                    "messages": [{"role": "user", "content": body.user}],
                })
                sig_headers = _sign_v4("POST", b_url, b_body, api_key, secret, region, "bedrock")
                resp = await client.post(b_url, headers=sig_headers, content=b_body)
            elif body.provider == "gemini":
                # Pilot already managed a Gemini key (settings.py validates one
                # and pushes it to the modules) but had no branch to spend it:
                # a Gemini call fell through to the OpenAI shape and failed.
                from urllib.parse import quote as _q
                g_url = provider_conf["endpoint"].format(model=_q(body.model, safe=""))
                resp = await client.post(
                    g_url,
                    headers={"Content-Type": "application/json",
                             "x-goog-api-key": api_key},
                    json={
                        "systemInstruction": {"parts": [{"text": body.system}]},
                        "contents": [{"role": "user", "parts": [{"text": body.user}]}],
                        "generationConfig": {"maxOutputTokens": AI_MAX_TOKENS},
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
                        "model": body.model,
                        "max_tokens": AI_MAX_TOKENS,
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
        parts = (data.get("candidates", [{}])[0].get("content", {}) or {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts)
    else:
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if _hit_output_cap(body.provider, data):
        # The provider answers 200 with a reply cut mid-sentence. Returning it
        # as-is pushed the failure to the caller, which reported "invalid AI
        # response" — blaming the model for a cap we set. Grouping a large
        # action plan produces JSON well past 4096 tokens, so this fired on
        # exactly the operations that matter.
        raise HTTPException(
            status_code=502,
            detail=(f"AI reply truncated at the {AI_MAX_TOKENS}-token output cap. "
                    "Narrow the request (fewer items at once) or raise "
                    "AI_MAX_TOKENS."))
    return AICompleteResponse(text=text)


@router.get("/config", response_model=AIConfigResponse)
async def get_ai_config(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return AIConfigResponse(
        anthropic_configured=bool(await _get_api_key("anthropic", db)),
        openai_configured=bool(await _get_api_key("openai", db)),
        providers=AI_PROVIDERS,
    )
