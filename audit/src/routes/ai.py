"""Audit AI endpoints — common proxy only (phase 1).

Everything generic (provider dispatch, /api/ai/complete, /runtime,
/config, /keys, managed mode) comes from src/ai_proxy_common.py. Audit
domain-specific prompts (finding suggestions, report wording) will be added here
when the feature lands.
"""
from __future__ import annotations

from src.ai_proxy_common import make_ai_router

router = make_ai_router()
