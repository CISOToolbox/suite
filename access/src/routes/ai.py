"""Access AI endpoints.

Access exposes only the shared /api/ai proxy (provider registry, key/settings
management, /complete, /runtime, /config, /keys, /validate-key, the LLM
dispatch) — it has no métier suggestion endpoint of its own. All of that lives
in src/ai_proxy_common.py.
"""
from __future__ import annotations

from src.ai_proxy_common import make_ai_router

router = make_ai_router()
