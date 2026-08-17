"""Design regression (H4 phase 3): asset migrated to the shared AI proxy.

routes/ai.py dropped from 649 to ~250 lines (provider plumbing now in
src/ai_proxy_common.py); its four asset-inventory suggestion endpoints stay.
This confirms the router still exposes the common endpoints plus all four
métier ones.
"""
import os
import sys

os.environ.setdefault("MODULE_NAME", "asset")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes.ai import router  # noqa: E402


def test_router_exposes_common_and_all_metier_endpoints():
    paths = {r.path for r in router.routes}
    for p in (
        "/api/ai/complete", "/api/ai/runtime", "/api/ai/config",
        "/api/ai/keys", "/api/ai/validate-key",           # common
        "/api/ai/asset/suggest-description",
        "/api/ai/asset/suggest-principe",
        "/api/ai/asset/suggest-raci",
        "/api/ai/asset/suggest-policies",                  # asset métier
    ):
        assert p in paths, f"missing endpoint: {p}"
