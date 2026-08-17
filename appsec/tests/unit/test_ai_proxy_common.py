"""Design regression (H4 phase 4): appsec migrated to the shared AI proxy.

routes/ai.py shrank (provider plumbing now in src/ai_proxy_common.py); the
finding-triage métier (NVD enrichment, prompt, analyze endpoint) stays. This
confirms the router still exposes the common endpoints plus /appsec/analyze-finding.
Migrating also fixes the historical _parse_json_lax drift (appsec only handled
objects) — the shared parser handles arrays too.
"""
import os
import sys

os.environ.setdefault("MODULE_NAME", "appsec")
os.environ.setdefault("JWT_SECRET", "test-secret")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.ai_proxy_common import _parse_json_lax  # noqa: E402
from src.routes.ai import router  # noqa: E402


def test_router_exposes_common_and_analyze_endpoint():
    paths = {r.path for r in router.routes}
    for p in (
        "/api/ai/complete", "/api/ai/runtime", "/api/ai/config",
        "/api/ai/keys", "/api/ai/validate-key",
        "/api/ai/appsec/analyze-finding",
    ):
        assert p in paths, f"missing endpoint: {p}"


def test_shared_parser_now_handles_arrays():
    # The drift bug: appsec's old _parse_json_lax matched only {...}. The shared
    # one accepts arrays too.
    assert _parse_json_lax('[{"a": 1}]') == [{"a": 1}]
    assert _parse_json_lax('{"a": 1}') == {"a": 1}
