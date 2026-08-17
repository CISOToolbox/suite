"""Active Directory / LDAP plugin — fetches computer objects and
maps them to AssetRecord rows.

Mirrors the `tools/ad_computers_to_asset_csv.py` script but pulls
directly into the DB via the plugin framework.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from src.plugins.base import (
    AssetPlugin, AssetRecord, SyncResult,
    strip_domain as _strip_domain,
)

logger = logging.getLogger("asset-backend")

UAC_ACCOUNTDISABLE = 0x0002
_PING_WORKERS = 50
_PING_TIMEOUT_S = 1.0
# We can't do ICMP ping from an unprivileged container, so we probe
# the two ports that are reliably open on a live Windows AD-joined
# host (445 SMB, 135 RPC endpoint-mapper). If either accepts a TCP
# handshake, we consider the host up.
_PROBE_PORTS = (445, 135)


def _probe_host(host: str) -> tuple[str, bool]:
    """Resolve DNS + TCP-probe. Returns (resolved_ip, reachable).

    A host is considered reachable if the TCP handshake succeeds on
    at least one of the Windows service ports listed in _PROBE_PORTS.
    This avoids the ICMP/root requirement of real ping while still
    detecting powered-off machines and dead DNS entries.
    """
    if not host:
        return ("", False)
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return ("", False)
    for port in _PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=_PING_TIMEOUT_S):
                return (ip, True)
        except OSError:
            continue
    return (ip, False)


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_dt(ft: Any) -> datetime | None:
    try:
        n = int(ft)
    except (TypeError, ValueError):
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


def _validate_ldap_url(url: str) -> str | None:
    """Block loopback + cloud metadata only. Private RFC1918 targets
    are the norm for AD and must be allowed."""
    from urllib.parse import urlparse
    u = url.strip()
    if not re.match(r"^ldaps?://", u, re.IGNORECASE):
        return "URL must start with ldap:// or ldaps://"
    parsed = urlparse(u)
    host = (parsed.hostname or "").lower()
    for b in ("127.", "::1", "localhost", "169.254.",
              "metadata.google.internal", "metadata.internal"):
        if host.startswith(b) or host == b.rstrip("."):
            return f"Blocked host: {host}"
    return None


# Characters allowed in a raw LDAP filter string. Parentheses, boolean
# operators, wildcard, equality/comparison markers, OID colon, plus the
# usual attribute/DN characters. This blocks null bytes, quoting, and
# anything that could smuggle a second filter or break the parser.
_LDAP_FILTER_ALLOWED = re.compile(
    r"^[A-Za-z0-9_.:\-=*()&|!<>/,\s@']+$"
)


def _validate_ldap_filter(f: str) -> str | None:
    """Reject connector-provided filters that contain suspicious chars.
    Returns None if safe, else an error string. Parens count must also
    balance — an unbalanced filter either crashes ldap3 or silently
    widens the query scope."""
    if not f:
        return None
    if len(f) > 2000:
        return "Filter too long"
    if not _LDAP_FILTER_ALLOWED.match(f):
        return "Filter contains disallowed characters"
    if f.count("(") != f.count(")"):
        return "Unbalanced parentheses in filter"
    return None


def _validate_base_dn(dn: str) -> str | None:
    """Base-DN must look like a DN (comma-separated `key=value` RDNs)
    and contain nothing that could inject a filter fragment."""
    if not dn:
        return None
    if len(dn) > 1000:
        return "Base DN too long"
    if "\x00" in dn or "(" in dn or ")" in dn or "*" in dn:
        return "Base DN contains disallowed characters"
    return None


def _ou_from_dn(dn: str) -> str:
    if not dn:
        return ""
    for p in (p.strip() for p in dn.split(",")):
        if p.upper().startswith("OU="):
            return p[3:]
    return ""


def _classify_type(os_string: str) -> str:
    low = (os_string or "").lower()
    if "server" in low:
        return "serveur_physique"
    return "poste_physique"


def _test_ldap(config: dict) -> dict:
    from ldap3 import ALL, SUBTREE, Connection, Server

    ldap_url = config.get("ldap_url", "").strip()
    bind_dn = config.get("bind_dn", "").strip()
    bind_password = config.get("bind_password", "")
    base_dn = config.get("base_dn", "").strip()
    use_ssl = config.get("use_ssl", False)

    if not ldap_url or not bind_dn or not base_dn:
        return {"ok": False, "error": "Missing required fields", "details": ""}

    url_err = _validate_ldap_url(ldap_url)
    if url_err:
        return {"ok": False, "error": url_err, "details": ""}
    dn_err = _validate_base_dn(base_dn)
    if dn_err:
        return {"ok": False, "error": dn_err, "details": ""}

    use_ssl_conn = ldap_url.lower().startswith("ldaps://") or bool(use_ssl)
    try:
        server = Server(ldap_url, use_ssl=use_ssl_conn, get_info=ALL, connect_timeout=10)
        conn = Connection(
            server, user=bind_dn, password=bind_password,
            auto_bind=True, auto_referrals=False, receive_timeout=10,
        )
    except Exception as e:
        return {"ok": False, "error": f"Connection failed: {type(e).__name__}", "details": ""}

    try:
        conn.search(
            search_base=base_dn, search_filter="(objectClass=*)",
            search_scope=SUBTREE, attributes=["distinguishedName"], size_limit=1,
        )
        count = len(conn.entries)
        conn.unbind()
        return {
            "ok": True, "error": "",
            "details": f"Connected to {server.host}. Base DN '{base_dn}' OK ({count} entry).",
        }
    except Exception as e:
        conn.unbind()
        return {"ok": False, "error": f"Search failed: {type(e).__name__}", "details": ""}


def _sync_ldap(config: dict, filters: dict) -> SyncResult:
    from ldap3 import ALL, SUBTREE, Connection, Server

    ldap_url = config.get("ldap_url", "").strip()
    bind_dn = config.get("bind_dn", "").strip()
    bind_password = config.get("bind_password", "")
    base_dn = config.get("base_dn", "").strip()
    use_ssl = config.get("use_ssl", False)
    # Default filter: all computer objects, including disabled (we
    # tag them as statut=inactif and keep the row for traceability)
    user_filter = (filters.get("computer_filter") or
                   config.get("computer_filter") or
                   "(objectClass=computer)").strip()
    # exclude_disabled: skip UAC_ACCOUNTDISABLE rows entirely
    exclude_disabled = bool(config.get("exclude_disabled", False))
    # strip_domain: keep only the hostname portion (before the first dot)
    strip_domain = bool(config.get("strip_domain", False))
    # ping_check: probe each host; unreachable → statut=inactif + IP in notes
    ping_check = bool(config.get("ping_check", False))

    if not ldap_url or not bind_dn or not base_dn:
        return SyncResult(errors=["Missing required config"])

    url_err = _validate_ldap_url(ldap_url)
    if url_err:
        return SyncResult(errors=[f"Invalid LDAP URL: {url_err}"])
    dn_err = _validate_base_dn(base_dn)
    if dn_err:
        return SyncResult(errors=[f"Invalid base DN: {dn_err}"])
    filter_err = _validate_ldap_filter(user_filter)
    if filter_err:
        return SyncResult(errors=[f"Invalid filter: {filter_err}"])

    use_ssl_conn = ldap_url.lower().startswith("ldaps://") or bool(use_ssl)
    server = Server(ldap_url, use_ssl=use_ssl_conn, get_info=ALL, connect_timeout=10)
    conn = Connection(
        server, user=bind_dn, password=bind_password,
        auto_bind=True, auto_referrals=False, receive_timeout=30,
    )

    attributes = [
        "cn", "dNSHostName", "sAMAccountName",
        "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
        "description", "distinguishedName",
        "userAccountControl", "lastLogonTimestamp", "whenCreated",
    ]

    assets: list[AssetRecord] = []
    errors: list[str] = []
    try:
        entry_gen = conn.extend.standard.paged_search(
            search_base=base_dn, search_filter=user_filter,
            search_scope=SUBTREE, attributes=attributes,
            paged_size=500, generator=True,
        )
        for entry in entry_gen:
            if entry.get("type") != "searchResEntry":
                continue
            raw = entry.get("attributes", {})
            a = {k.lower(): v for k, v in raw.items()}

            uac = int(a.get("useraccountcontrol", 0) or 0)
            is_disabled = bool(uac & UAC_ACCOUNTDISABLE)
            if is_disabled and exclude_disabled:
                continue

            os_string = a.get("operatingsystem", "") or ""
            os_version = a.get("operatingsystemversion", "") or ""
            sp = a.get("operatingsystemservicepack", "") or ""
            if sp and sp not in os_version:
                os_version = f"{os_version} {sp}".strip()

            dns_host = a.get("dnshostname", "") or ""
            cn = a.get("cn", "") or ""
            sam = a.get("samaccountname", "") or ""
            nom = dns_host or cn or sam
            if not nom:
                continue
            if strip_domain:
                nom = _strip_domain(nom)
            # The sAMAccountName without $ is the canonical stable key
            external_key = (sam.rstrip("$") or cn).lower()

            dn = a.get("distinguishedname", "") or ""
            localisation = _ou_from_dn(dn)

            description = a.get("description", "") or ""
            if isinstance(description, list):
                description = "; ".join(description)

            llt_raw = a.get("lastlogontimestamp")
            if isinstance(llt_raw, datetime):
                last_login_at = llt_raw if llt_raw.tzinfo else llt_raw.replace(tzinfo=timezone.utc)
            else:
                last_login_at = _filetime_to_dt(llt_raw)

            notes_bits: list[str] = []
            when_created = a.get("whencreated")
            if isinstance(when_created, datetime):
                notes_bits.append(f"created={when_created.date().isoformat()}")
            if dn:
                notes_bits.append(f"dn={dn}")
            notes = " | ".join(notes_bits)

            assets.append(AssetRecord(
                external_key=external_key,
                nom=nom,
                type=_classify_type(os_string),
                description=description,
                criticite=3 if "server" in os_string.lower() else 2,
                localisation=localisation,
                os=os_string,
                version=os_version,
                statut="inactif" if is_disabled else "actif",
                notes=notes,
                last_login_at=last_login_at,
                raw_data={
                    "sAMAccountName": sam,
                    "dNSHostName": dns_host,
                    "distinguishedName": dn,
                    "userAccountControl": uac,
                    "disabled": is_disabled,
                },
            ))

        logger.info("LDAP asset sync: %d assets collected", len(assets))

        if ping_check and assets:
            logger.info("LDAP asset sync: pinging %d hosts (workers=%d, timeout=%ds)",
                        len(assets), _PING_WORKERS, _PING_TIMEOUT_S)
            targets = []
            for ar in assets:
                fqdn = (ar.raw_data.get("dNSHostName") or "").strip() if ar.raw_data else ""
                targets.append(fqdn or ar.nom)
            with ThreadPoolExecutor(max_workers=_PING_WORKERS) as ex:
                results = list(ex.map(_probe_host, targets))
            reachable = sum(1 for _, ok in results if ok)
            logger.info("LDAP asset sync: ping done — %d reachable / %d total",
                        reachable, len(results))
            for ar, (ip, ok) in zip(assets, results):
                if ip:
                    ar.ip_address = ip
                note_extras = []
                note_extras.append("reachable=yes" if ok else "reachable=no")
                ar.notes = (ar.notes + " | " if ar.notes else "") + " | ".join(note_extras)
                if not ok and ar.statut == "actif":
                    # Note: unreachable ≠ necessarily powered off. A host-
                    # firewall rule or network segmentation will also cause
                    # both probe ports (445/135) to drop connect attempts.
                    # We still mark inactive because that's the best signal
                    # we have from the container's network vantage point.
                    logger.debug(
                        "LDAP asset sync: %s unreachable on %s — "
                        "downgrading to statut=inactif",
                        ar.nom, _PROBE_PORTS)
                    ar.statut = "inactif"
    except Exception as e:
        errors.append(f"LDAP search error: {type(e).__name__}")
        logger.exception("LDAP asset sync failed")
    finally:
        conn.unbind()

    return SyncResult(assets=assets, errors=errors)


class LdapAdAssetPlugin(AssetPlugin):
    plugin_type = "ldap_ad"
    label = "Active Directory (LDAP) — computers"
    label_en = "Active Directory (LDAP) — computers"
    config_schema = [
        {"key": "ldap_url", "label": "URL du serveur LDAP", "label_en": "LDAP Server URL",
         "type": "text", "required": True, "placeholder": "ldap://dc.corp.local:389"},
        {"key": "bind_dn", "label": "Bind DN", "label_en": "Bind DN",
         "type": "text", "required": True,
         "placeholder": "CN=svc-ciso-asset,OU=ServiceAccounts,DC=corp,DC=local"},
        {"key": "bind_password", "label": "Mot de passe Bind", "label_en": "Bind Password",
         "type": "password", "required": True},
        {"key": "base_dn", "label": "Base DN (recherche)", "label_en": "Base DN",
         "type": "text", "required": True, "placeholder": "DC=corp,DC=local"},
        {"key": "computer_filter", "label": "Filtre LDAP", "label_en": "LDAP filter",
         "type": "text", "required": False,
         "placeholder": "(objectClass=computer)"},
        {"key": "use_ssl", "label": "Utiliser SSL/LDAPS", "label_en": "Use SSL/LDAPS",
         "type": "checkbox", "required": False},
        {"key": "exclude_disabled", "label": "Exclure les comptes désactivés",
         "label_en": "Exclude disabled accounts", "type": "checkbox", "required": False},
        {"key": "strip_domain", "label": "Ne garder que le hostname (sans domaine)",
         "label_en": "Keep hostname only (strip domain)", "type": "checkbox", "required": False},
        {"key": "ping_check", "label": "Pinger chaque hôte — marquer inactif si injoignable",
         "label_en": "Ping each host — mark inactive if unreachable",
         "type": "checkbox", "required": False},
    ]
    setup_guide = (
        "1. Créer un compte de service dédié dans l'AD (ex: svc-ciso-asset)\n"
        "2. Droits minimum : lecture sur les objets computer et attributs dérivés\n"
        "3. Utiliser LDAPS (636) en prod. LDAP clair (389) transmet le bind password en clair.\n"
        "4. Filtres utiles :\n"
        "   - Tous les serveurs : (&(objectClass=computer)(operatingSystem=*Server*))\n"
        "   - Postes uniquement : (&(objectClass=computer)(!(operatingSystem=*Server*)))\n"
        "5. `lastLogonTimestamp` n'est répliqué qu'une fois tous les 9-14 jours par défaut.\n"
        "6. Options :\n"
        "   - \"Exclure désactivés\" ignore les objets marqués UAC=2 (ACCOUNTDISABLE)\n"
        "   - \"Ne garder que le hostname\" tronque le FQDN avant le premier point\n"
        "   - \"Pinger chaque hôte\" teste un TCP handshake sur les ports 445/135.\n"
        "     Les hôtes injoignables sont marqués statut=inactif, l'IP est ajoutée\n"
        "     dans les notes. Le conteneur doit avoir un accès réseau vers les\n"
        "     machines cibles (timeout 1s par hôte, 50 workers)."
    )
    setup_guide_en = (
        "1. Create a dedicated AD service account (e.g. svc-ciso-asset)\n"
        "2. Minimum rights: read on computer objects and related attributes\n"
        "3. Use LDAPS (636) in production — plain LDAP (389) sends the bind password in cleartext.\n"
        "4. Useful filters:\n"
        "   - Servers only: (&(objectClass=computer)(operatingSystem=*Server*))\n"
        "   - Workstations only: (&(objectClass=computer)(!(operatingSystem=*Server*)))\n"
        "5. `lastLogonTimestamp` is replicated only every 9-14 days by default.\n"
        "6. Options:\n"
        "   - \"Exclude disabled\" skips objects with UAC=2 (ACCOUNTDISABLE)\n"
        "   - \"Keep hostname only\" truncates the FQDN before the first dot\n"
        "   - \"Ping each host\" performs a TCP handshake on ports 445/135.\n"
        "     Unreachable hosts are set to statut=inactif, the IP is recorded\n"
        "     in notes. The container must have network access to the targets\n"
        "     (1s timeout per host, 50 workers)."
    )

    async def test_connection(self, config: dict) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _test_ldap, config)

    async def sync(self, config: dict, filters: dict) -> SyncResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync_ldap, config, filters)
