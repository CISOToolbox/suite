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

router = APIRouter(prefix="/api/ai", tags=["ai"])

AI_PROVIDERS = {
    "anthropic": {
        "label": "Anthropic (Claude)",
        "models": [
            {"id": "claude-opus-4-8", "label": "Claude Opus 4.8"},
            {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
            {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5"},
            {"id": "claude-opus-4-6", "label": "Claude Opus 4.6"},
        ],
        "defaultModel": "claude-sonnet-4-6",
        "endpoint": "https://api.anthropic.com/v1/messages",
    },
    "openai": {
        "label": "OpenAI (GPT)",
        "models": [
            {"id": "gpt-5.5", "label": "GPT-5.5"},
            {"id": "gpt-5.5-pro", "label": "GPT-5.5 Pro"},
            {"id": "gpt-5.4-mini", "label": "GPT-5.4 mini"},
            {"id": "gpt-4o", "label": "GPT-4o"},
            {"id": "gpt-4o-mini", "label": "GPT-4o mini"},
        ],
        "defaultModel": "gpt-5.5",
        "endpoint": "https://api.openai.com/v1/chat/completions",
    },
    "bedrock": {
        "label": "AWS Bedrock",
        "models": [
            {"id": "anthropic.claude-sonnet-4-6-20250514-v1:0", "label": "Claude Sonnet 4.6 (Bedrock)"},
            {"id": "anthropic.claude-haiku-4-5-20251001-v1:0", "label": "Claude Haiku 4.5 (Bedrock)"},
        ],
        "defaultModel": "anthropic.claude-sonnet-4-6-20250514-v1:0",
        "endpoint": "https://bedrock-runtime.{region}.amazonaws.com",
    },
}


async def _get_setting(key: str, db: AsyncSession) -> str:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    return (s.value if s and s.value else "") or ""


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


async def _get_api_key(provider: str, db: AsyncSession) -> str | None:
    key_name = f"ai_key_{provider}"
    result = await db.execute(select(AppSettings).where(AppSettings.key == key_name))
    setting = result.scalar_one_or_none()
    if setting and setting.value:
        return setting.value
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
                        "max_tokens": 4096,
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
    else:
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    return AICompleteResponse(text=text)


@router.get("/config", response_model=AIConfigResponse)
async def get_ai_config(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return AIConfigResponse(
        anthropic_configured=bool(await _get_api_key("anthropic", db)),
        openai_configured=bool(await _get_api_key("openai", db)),
        providers=AI_PROVIDERS,
    )
