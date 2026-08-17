"""Plugin framework for external asset sources (AD, Intune, EDR…).

Each plugin subclass implements `test_connection()` and `sync()`.
The sync result is a list of `AssetRecord`s that the router upserts
into the Asset table by matching on `external_key` (stable unique id
from the source system — e.g. the AD sAMAccountName or the Intune
managedDeviceId). `nom` is used as a fallback match for legacy rows.

Plugin types registered in `src/plugins/__init__.py::PLUGIN_REGISTRY`.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


def strip_domain(name: str) -> str:
    """Return just the hostname portion of a FQDN (everything before
    the first dot). Used by plugins that expose a 'strip_domain'
    option to normalise asset names."""
    if not name:
        return name
    return name.split(".", 1)[0]


def validate_public_http_url(url: str) -> str | None:
    """Defend against SSRF: only allow http(s) URLs whose hostname
    resolves to a **public** IP. Returns an error string on failure,
    None on success. Used by any connector targeting a public SaaS
    (Cloud Temple, GitHub, etc.). NOT suitable for on-prem connectors
    that legitimately target RFC1918 (see plugins/ldap_ad.py for the
    looser variant).
    """
    u = (url or "").strip()
    if not re.match(r"^https?://", u, re.IGNORECASE):
        return "Base URL must start with http(s)://"
    parsed = urllib.parse.urlparse(u)
    host = (parsed.hostname or "").lower()
    if not host:
        return "Missing host in URL"
    for b in ("localhost", "metadata.google.internal", "metadata.internal"):
        if host == b or host.endswith("." + b):
            return f"Blocked host: {host}"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return f"DNS resolution failed: {e}"
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved
                or addr.is_unspecified):
            return f"Blocked: {host} resolves to internal IP {addr}"
    return None


@dataclass
class AssetRecord:
    """Normalised asset returned by a plugin. The router maps these
    fields 1-to-1 onto the Asset table columns. Any field left empty
    is not overwritten on re-sync (preserves manual edits)."""
    # Required — stable source-side identifier (never changes for a given
    # device in the source). Used as the upsert key.
    external_key: str
    # Required — human label shown in the Asset list.
    nom: str
    # Categorisation — mapped to the Asset.type enum
    # (serveur_physique / poste_physique / …)
    type: str = "application"
    # Optional fields
    description: str = ""
    criticite: int = 2            # 1..5
    proprietaire: str = ""
    localisation: str = ""
    os: str = ""
    version: str = ""
    fournisseur: str = ""
    fin_support: str = ""
    fin_vie: str = ""
    statut: str = "actif"         # actif / inactif / en_cours / retire
    notes: str = ""
    ip_address: str = ""
    last_login_at: datetime | None = None
    # Raw passthrough for plugin-specific fields the router doesn't map.
    raw_data: dict = field(default_factory=dict)


@dataclass
class SyncResult:
    assets: list[AssetRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class AssetPlugin(ABC):
    """Each concrete plugin declares these class attributes so the UI
    can render an "Add connector" form without knowing the specifics."""
    plugin_type: str = ""
    label: str = ""
    label_en: str = ""
    # [{key, label, label_en, type, required, placeholder}]
    # type ∈ {text, password, checkbox, select, textarea, number}
    config_schema: list[dict] = []
    setup_guide: str = ""
    setup_guide_en: str = ""

    @abstractmethod
    async def test_connection(self, config: dict) -> dict:
        """Return {ok: bool, error: str, details: str}."""

    @abstractmethod
    async def sync(self, config: dict, filters: dict) -> SyncResult:
        """Fetch the asset inventory from the external source."""
