"""Design regression (H4 phase 3): access migrated to the shared AI proxy.

Access has no métier suggestion endpoint, so routes/ai.py is now just
`router = make_ai_router()` (409 → ~12 lines). This test confirms the shared
/api/ai endpoints are still exposed.
"""
import os
import sys

os.environ.setdefault("MODULE_NAME", "access")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.routes.ai import router  # noqa: E402


def test_router_exposes_the_common_endpoints():
    paths = {r.path for r in router.routes}
    for p in (
        "/api/ai/complete", "/api/ai/runtime", "/api/ai/config",
        "/api/ai/keys", "/api/ai/validate-key",
    ):
        assert p in paths, f"missing endpoint: {p}"
