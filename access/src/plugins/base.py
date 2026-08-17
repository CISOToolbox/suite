from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from src.ssrf_guard import validate_public_url

# Self-hosted Keycloak / GitLab instances legitimately live on RFC1918, so LAN
# addresses CAN be accepted here (unlike the SaaS-only guard in
# asset/src/plugins/base.py) — but no longer by default. This used to default
# to true while the sibling blocklist the comment promised did not exist, so
# `http://pilot-app:8080/api/internal/...` passed with the connector PAT
# attached. ssrf_guard now carries that list (_DOCKER_SIBLING_NAMES), and the
# default is opt-in: a deployment that really needs an on-prem connector sets
# ALLOW_PRIVATE_CONNECTOR_URLS=true and takes that decision knowingly.
# Loopback, link-local, suite siblings and every cloud-metadata endpoint stay
# blocked either way.
_ALLOW_PRIVATE_CONNECTOR_URLS = os.getenv(
    "ALLOW_PRIVATE_CONNECTOR_URLS", "false"
).lower() in ("1", "true", "yes")


def validate_connector_base_url(url: str) -> str:
    """Validate an admin-supplied connector base URL, SSRF-wise.

    The client secret / PAT of the connector is sent to whatever this URL
    points at, so a compromised admin account could otherwise use it to
    exfiltrate credentials or reach the cloud-metadata service. Returns the
    trimmed URL; raises ValueError with a readable reason.
    """
    u = (url or "").strip()
    if not u:
        raise ValueError("Base URL required")
    validate_public_url(u, allow_private=_ALLOW_PRIVATE_CONNECTOR_URLS)
    return u.rstrip("/")


@dataclass
class UserRecord:
    email: str
    display_name: str = ""
    # Structured identity, when the source exposes it. Used for the review
    # display and as a fallback for SI matching when the email doesn't
    # resolve. Empty when the connector only has an email/login.
    nom: str = ""
    prenom: str = ""
    type_compte: str = "personnel"
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    # Last login date/time fetched from the source. None if the
    # connector doesn't expose it or the account never logged in.
    last_login_at: datetime | None = None
    # IdP account active/enabled state (Entra accountEnabled, Okta status,
    # GitLab state, Google suspended, etc.). None when the connector doesn't
    # expose it or the account was entered manually.
    account_enabled: bool | None = None


@dataclass
class SyncResult:
    users: list[UserRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class AccessPlugin(ABC):
    plugin_type: str = ""
    label: str = ""
    label_en: str = ""
    config_schema: list[dict] = []  # [{key, label, label_en, type, required, placeholder}]
    setup_guide: str = ""
    setup_guide_en: str = ""
    # File-import connectors set this True. Instead of calling an API, they
    # parse a file uploaded at sync time: the review import route reads the
    # upload and injects it into the config as ``file_b64`` before calling
    # ``sync()``. Such connectors are imported via the multipart endpoint
    # ``import-connector-file``, not the JSON ``import-connector``.
    accepts_file: bool = False

    @abstractmethod
    async def test_connection(self, config: dict) -> dict:
        """Returns {ok: bool, error: str, details: str}"""

    @abstractmethod
    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        """Fetch users and their access rights from the external platform."""
