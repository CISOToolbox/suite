from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

# userAccountControl flags
UAC_ACCOUNTDISABLE = 0x0002

# AD stores lastLogonTimestamp as Windows FILETIME: 100-nanosecond
# intervals since 1601-01-01 UTC. Convert to a Python datetime.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_dt(ft: Any) -> datetime | None:
    """Convert an AD FILETIME integer to an aware UTC datetime.
    Returns None for 0 (never logged in), very large placeholder
    values (9223372036854775807 = "never expires"), or parse errors."""
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


def _parse_group_cn(dn: str) -> str:
    """Extract CN from a distinguishedName: 'CN=Domain Admins,CN=Users,DC=example,DC=com' -> 'Domain Admins'."""
    if dn.upper().startswith("CN="):
        return dn[3:].split(",", 1)[0]
    return dn


def _ensure_list(value: Any) -> list:
    """memberOf can be a single string or a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _validate_ldap_url(url: str) -> str | None:
    """Validate LDAP URL: must be ldap:// or ldaps://. Reject loopback
    and cloud-metadata endpoints (SSRF defence). Private/RFC1918 targets
    are allowed — Active Directory domain controllers are always on the
    corporate LAN, so blocking 10.x / 172.16-31.x / 192.168.x would
    make the plugin unusable in its normal use case."""
    import re
    from urllib.parse import urlparse
    url = url.strip()
    if not re.match(r'^ldaps?://', url, re.IGNORECASE):
        return "URL must start with ldap:// or ldaps://"
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    # Block loopback, link-local, and common cloud metadata endpoints only.
    blocked = [
        "127.", "::1", "localhost",
        "169.254.",                        # link-local incl. AWS/GCP metadata
        "metadata.google.internal",
        "metadata.internal",
    ]
    for b in blocked:
        if host.startswith(b) or host == b.rstrip("."):
            return f"Blocked host: {host}"
    return None


def _validate_ldap_filter(f: str) -> str | None:
    """Basic LDAP filter validation — reject dangerous patterns."""
    import re
    if not f.startswith("(") or not f.endswith(")"):
        return "Filter must be enclosed in parentheses"
    if re.search(r'[;\x00-\x1f]', f):
        return "Filter contains invalid characters"
    return None


def _sync_ldap(config: dict, group_filters: list[str]) -> SyncResult:
    import ldap3
    from ldap3 import ALL, SUBTREE, Connection, Server

    ldap_url = config.get("ldap_url", "").strip()
    bind_dn = config.get("bind_dn", "").strip()
    bind_password = config.get("bind_password", "")
    base_dn = config.get("base_dn", "").strip()
    user_filter = config.get("user_filter", "").strip() or "(&(objectClass=user)(objectCategory=person))"
    use_ssl = config.get("use_ssl", False)

    if not ldap_url or not bind_dn or not base_dn:
        return SyncResult(errors=["Missing required config: ldap_url, bind_dn, base_dn"])

    url_err = _validate_ldap_url(ldap_url)
    if url_err:
        return SyncResult(errors=[f"Invalid LDAP URL: {url_err}"])

    filter_err = _validate_ldap_filter(user_filter)
    if filter_err:
        return SyncResult(errors=[f"Invalid LDAP filter: {filter_err}"])

    use_ssl_conn = ldap_url.lower().startswith("ldaps://") or bool(use_ssl)

    server = Server(ldap_url, use_ssl=use_ssl_conn, get_info=ALL, connect_timeout=10)
    conn = Connection(
        server,
        user=bind_dn,
        password=bind_password,
        auto_bind=True,
        auto_referrals=False,
        receive_timeout=30,
    )

    attributes = [
        "sAMAccountName", "mail", "displayName", "memberOf",
        "userAccountControl", "distinguishedName", "department", "title",
        "lastLogonTimestamp",
    ]

    users: list[UserRecord] = []
    errors: list[str] = []

    # Normalize group filters for case-insensitive matching
    group_filters_lower = [g.lower() for g in group_filters] if group_filters else []

    try:
        entry_generator = conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=500,
            generator=True,
        )

        count = 0
        with_llt = 0
        for entry in entry_generator:
            if entry.get("type") != "searchResEntry":
                continue

            attrs_raw = entry.get("attributes", {})
            # Case-insensitive access: AD attribute names are
            # case-insensitive on the server but some ldap3 versions
            # preserve the server-side casing in the dict keys.
            attrs = {k.lower(): v for k, v in attrs_raw.items()}
            count += 1

            # Parse groups
            member_of_raw = _ensure_list(attrs.get("memberof"))
            group_cns = [_parse_group_cn(dn) for dn in member_of_raw]

            # Apply group filter: if specified, skip users not in any filtered group
            if group_filters_lower:
                matched = any(g.lower() in group_filters_lower for g in group_cns)
                if not matched:
                    continue

            mail = attrs.get("mail", "") or ""
            sam = attrs.get("samaccountname", "") or ""
            display_name = attrs.get("displayname", "") or ""
            uac = int(attrs.get("useraccountcontrol", 0) or 0)
            department = attrs.get("department", "") or ""
            title = attrs.get("title", "") or ""
            dn = attrs.get("distinguishedname", "") or ""
            last_logon_raw = attrs.get("lastlogontimestamp")
            # ldap3 may return a datetime directly or the raw FILETIME int
            if isinstance(last_logon_raw, datetime):
                last_login_at = last_logon_raw if last_logon_raw.tzinfo else last_logon_raw.replace(tzinfo=timezone.utc)
            else:
                last_login_at = _filetime_to_dt(last_logon_raw)
            if last_login_at:
                with_llt += 1

            # Determine account type
            is_disabled = bool(uac & UAC_ACCOUNTDISABLE)
            if is_disabled:
                type_compte = "desactive"
            elif not mail:
                type_compte = "service"
            else:
                type_compte = "personnel"

            email = mail if mail else sam

            users.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=[],
                groups=group_cns,
                last_login_at=last_login_at,
                account_enabled=(not is_disabled),
                raw_data={
                    "sAMAccountName": sam,
                    "mail": mail,
                    "displayName": display_name,
                    "memberOf": group_cns,
                    "userAccountControl": uac,
                    "distinguishedName": dn,
                    "department": department,
                    "title": title,
                    "disabled": is_disabled,
                    "lastLogonTimestamp": last_login_at.isoformat() if last_login_at else None,
                },
            ))

        logger.info("LDAP sync: found %d entries, %d users after filtering, %d with lastLogonTimestamp",
                    count, len(users), with_llt)

    except Exception as e:
        errors.append(f"LDAP search error: {e}")
        logger.error("LDAP search error: %s", e)
    finally:
        conn.unbind()

    return SyncResult(users=users, errors=errors)


def _test_ldap(config: dict) -> dict:
    import ldap3
    from ldap3 import ALL, SUBTREE, Connection, Server

    ldap_url = config.get("ldap_url", "").strip()
    bind_dn = config.get("bind_dn", "").strip()
    bind_password = config.get("bind_password", "")
    base_dn = config.get("base_dn", "").strip()
    use_ssl = config.get("use_ssl", False)

    if not ldap_url or not bind_dn or not base_dn:
        return {"ok": False, "error": "Missing required fields: ldap_url, bind_dn, base_dn", "details": ""}

    url_err = _validate_ldap_url(ldap_url)
    if url_err:
        return {"ok": False, "error": f"Invalid LDAP URL: {url_err}", "details": ""}

    use_ssl_conn = ldap_url.lower().startswith("ldaps://") or bool(use_ssl)

    try:
        server = Server(ldap_url, use_ssl=use_ssl_conn, get_info=ALL, connect_timeout=10)
        conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=True,
            auto_referrals=False,
            receive_timeout=10,
        )
    except Exception as e:
        return {"ok": False, "error": f"Connection failed: {e}", "details": ""}

    try:
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            size_limit=1,
        )
        count = len(conn.entries)
        conn.unbind()
        return {
            "ok": True,
            "error": "",
            "details": f"Connected to {server.host}. Base DN '{base_dn}' accessible ({count} entry found).",
        }
    except Exception as e:
        conn.unbind()
        return {"ok": False, "error": f"Search failed: {e}", "details": ""}


class LdapAdPlugin(AccessPlugin):
    plugin_type = "ldap_ad"
    label = "Active Directory (LDAP)"
    label_en = "Active Directory (LDAP)"
    config_schema = [
        {"key": "ldap_url", "label": "URL du serveur LDAP", "label_en": "LDAP Server URL", "type": "text", "required": True, "placeholder": "ldaps://dc.example.com:636"},
        {"key": "bind_dn", "label": "Bind DN", "label_en": "Bind DN", "type": "text", "required": True, "placeholder": "CN=svc-access,OU=Service Accounts,DC=example,DC=com"},
        {"key": "bind_password", "label": "Mot de passe Bind", "label_en": "Bind Password", "type": "password", "required": True},
        {"key": "base_dn", "label": "Base DN (recherche)", "label_en": "Base DN (search)", "type": "text", "required": True, "placeholder": "DC=example,DC=com"},
        {"key": "user_filter", "label": "Filtre utilisateurs", "label_en": "User filter", "type": "text", "required": False, "placeholder": "(&(objectClass=user)(objectCategory=person))"},
        {"key": "use_ssl", "label": "Utiliser SSL/STARTTLS", "label_en": "Use SSL/STARTTLS", "type": "checkbox", "required": False},
    ]
    setup_guide = (
        "1. Créer un compte de service dédié dans l'AD (ex: svc-ciso-access)\n"
        "2. Placer le compte dans une OU dédiée (ex: OU=Service Accounts)\n"
        "3. Attribuer les permissions minimales :\n"
        "   - Membre du groupe \"Domain Users\" (par défaut)\n"
        "   - Droit de lecture sur les objets utilisateur et groupe de la base DN cible\n"
        "   - Aucun droit d'écriture, aucun rôle administrateur\n"
        "4. Délégation de contrôle (optionnel, pour restreindre au minimum) :\n"
        "   - Clic droit sur l'OU cible > Déléguer le contrôle\n"
        "   - Sélectionner le compte svc-ciso-access\n"
        "   - Cocher uniquement \"Lire toutes les informations utilisateur\"\n"
        "5. Utiliser LDAPS (port 636) plutôt que LDAP (port 389) pour chiffrer la connexion\n"
        "6. Activer la politique \"Le mot de passe n'expire jamais\" ou configurer une rotation dans le module Comptes de service\n"
        "7. Le filtre utilisateurs par défaut est : (&(objectClass=user)(objectCategory=person))\n"
        "   Pour exclure les comptes désactivés : (&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))\n\n"
        "Permissions minimales : lecture seule sur les objets utilisateur et groupe (aucun droit d'écriture)"
    )
    setup_guide_en = (
        "1. Create a dedicated service account in AD (e.g. svc-ciso-access)\n"
        "2. Place the account in a dedicated OU (e.g. OU=Service Accounts)\n"
        "3. Assign minimum permissions:\n"
        "   - Member of \"Domain Users\" group (default)\n"
        "   - Read access on user and group objects in the target base DN\n"
        "   - No write permissions, no admin roles\n"
        "4. Delegation of control (optional, for tighter restriction):\n"
        "   - Right-click on target OU > Delegate Control\n"
        "   - Select the svc-ciso-access account\n"
        "   - Check only \"Read all user information\"\n"
        "5. Use LDAPS (port 636) instead of LDAP (port 389) to encrypt the connection\n"
        "6. Enable \"Password never expires\" or configure rotation in the Service Accounts module\n"
        "7. Default user filter: (&(objectClass=user)(objectCategory=person))\n"
        "   To exclude disabled accounts: (&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))\n\n"
        "Minimum permissions: read-only on user and group objects (no write access)"
    )

    async def test_connection(self, config: dict) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _test_ldap, config)

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync_ldap, config, group_filters)
