"""Lock the LDAP URL SSRF guard: block loopback/link-local/metadata
(including via DNS resolution), but ALLOW RFC1918 (on-prem AD is legit)."""
import os
import sys
from unittest.mock import patch

_ACCESS_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, _ACCESS_ROOT)
# ldap_generic is now a generic add-on (loaded dynamically at runtime).
sys.path.insert(0, os.path.join(_ACCESS_ROOT, "addons", "generic", "ldap_generic"))

from ldap_generic import _validate_ldap_url  # noqa: E402


def _resolves_to(ip):
    return [(2, 1, 6, "", (ip, 389))]


class TestLdapSsrfGuard:
    def test_scheme_required(self):
        assert _validate_ldap_url("http://dc.corp.local") is not None

    def test_string_blocked_hosts(self):
        for u in ("ldap://127.0.0.1", "ldaps://localhost", "ldap://169.254.169.254",
                  "ldap://metadata.google.internal"):
            assert _validate_ldap_url(u) is not None

    def test_rfc1918_allowed(self):
        # On-prem AD on the LAN must be reachable.
        with patch("socket.getaddrinfo", return_value=_resolves_to("10.1.2.3")):
            assert _validate_ldap_url("ldaps://dc01.corp.local") is None
        with patch("socket.getaddrinfo", return_value=_resolves_to("192.168.1.10")):
            assert _validate_ldap_url("ldap://ad.internal") is None

    def test_dns_rebind_to_loopback_blocked(self):
        # A hostname that passes the string check but RESOLVES to loopback.
        with patch("socket.getaddrinfo", return_value=_resolves_to("127.0.0.1")):
            assert _validate_ldap_url("ldaps://sneaky.example.com") is not None

    def test_dns_resolve_to_metadata_blocked(self):
        with patch("socket.getaddrinfo", return_value=_resolves_to("169.254.169.254")):
            assert _validate_ldap_url("ldaps://evil.example.com") is not None

    def test_unresolvable_passes_validation(self):
        # Unresolved -> let the bind fail naturally, don't hard-block.
        with patch("socket.getaddrinfo", side_effect=OSError("no such host")):
            assert _validate_ldap_url("ldaps://does-not-exist.corp") is None

    def test_public_allowed(self):
        with patch("socket.getaddrinfo", return_value=_resolves_to("8.8.8.8")):
            assert _validate_ldap_url("ldaps://ldap.public.example") is None
