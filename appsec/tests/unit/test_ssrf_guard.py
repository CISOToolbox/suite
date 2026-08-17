"""Regression (H2): the custom-LLM endpoint SSRF guard must exist in appsec.

appsec/routes/ai.py was a verbatim copy of surface's provider proxy, including
`from src.scanners import _resolve_safe_target`. appsec's scanners module
(Trivy/Gitleaks/Semgrep) has no such symbol, so every `provider="custom"` AI
call raised ImportError -> HTTP 500. The fix gives appsec its own `ssrf_guard`
(same contract as watch's: raise ValueError on an unsafe host) and imports it.
"""
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.ssrf_guard import resolve_safe_target  # noqa: E402


def _addrinfo(ip):
    return [(2, 1, 6, "", (ip, 0))]


# ── The guard blocks internal / metadata targets ────────────────────

@pytest.mark.parametrize("host", ["localhost", "metadata", "metadata.google.internal", ""])
def test_blocked_hostnames_raise(host):
    with pytest.raises(ValueError):
        resolve_safe_target(host)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254"])
def test_private_and_metadata_ips_blocked(ip):
    with patch("src.ssrf_guard.socket.getaddrinfo", return_value=_addrinfo(ip)):
        with pytest.raises(ValueError):
            resolve_safe_target("evil.example.com")


def test_public_ip_is_allowed():
    with patch("src.ssrf_guard.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        resolve_safe_target("example.com")  # must not raise


# ── Regression guard: the broken import is gone ─────────────────────

def test_ai_route_no_longer_imports_resolver_from_scanners():
    # The custom-LLM branch (and its SSRF guard) moved to the shared
    # ai_proxy_common.py during the AI-proxy factorization; the broken
    # `from src.scanners import _resolve_safe_target` must be gone from both,
    # and the correct guard present in the shared proxy.
    root = Path(__file__).parent.parent.parent / "src"
    ai_src = (root / "routes" / "ai.py").read_text()
    common = root / "ai_proxy_common.py"
    combined = ai_src + (common.read_text() if common.exists() else "")
    assert "from src.scanners import _resolve_safe_target" not in combined
    # resolve_safe_url, not resolve_safe_target: the latter only vetted the
    # hostname and then let httpx re-resolve it, leaving a DNS-rebinding window
    # on a request that carries the API key. The guard now returns a URL
    # pinned to the resolved IP, so that is what this asserts.
    assert "from src.ssrf_guard import resolve_safe_url" in combined
