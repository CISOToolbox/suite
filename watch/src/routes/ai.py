"""AI routes: the shared /api/ai proxy (src/ai_proxy_common.py).

Watch's own AI runs on the server (the phase-4 analysis, the digest), through
``call_llm_text`` below; the browser only reaches the common endpoints.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from src.ai_proxy_common import (  # noqa: F401 — re-exported for digest.py
    AI_PROVIDERS,
    _get_api_key,
    _runtime_provider_model,
    call_llm,
    make_ai_router,
)

router = make_ai_router()


async def call_llm_text(
    db: AsyncSession,
    system: str,
    user_prompt: str,
    provider: str | None = None,
    model: str | None = None,
    max_tokens: int = 4096,
) -> str:
    """Server-initiated LLM call (phase-4 analysis): the module's configured
    provider and model unless given, without the per-user rate limit nor the
    ai_enabled check — callers are trusted server code, not clients."""
    if not provider or not model:
        rp, rm = await _runtime_provider_model(db)
        provider = provider or rp
        model = model or rm
    return await call_llm(db, system, user_prompt, provider, model, max_tokens=max_tokens)
