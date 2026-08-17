from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")


def _ensure_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _parse_group_cn(dn: str) -> str:
    """Extract CN from a distinguishedName."""
    if dn.upper().startswith("CN="):
        return dn[3:].split(",", 1)[0]
    return dn


def _validate_ldap_url(url: str) -> str | None:
    """Validate LDAP URL: must be ldap:// or ldaps://. Reject loopback
    and cloud-metadata endpoints (SSRF defence). Private/RFC1918 targets
    are allowed — LDAP directories are typically on the internal LAN,
    so blocking those would make the plugin unusable."""
    import re
    from urllib.parse import urlparse
    url = url.strip()
    if not re.match(r'^ldaps?://', url, re.IGNORECASE):
        return "URL must start with ldap:// or ldaps://"
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return "Missing host"
    blocked = [
        "127.", "::1", "localhost",
        "169.254.",
        "metadata.google.internal",
        "metadata.internal",
    ]
    for b in blocked:
        if host.startswith(b) or host == b.rstrip("."):
            return f"Blocked host: {host}"
    # Resolve and re-check: a hostname pointing at loopback/link-local (or an
    # alternate IP encoding) must not bypass the string check above. RFC1918
    # stays allowed — on-prem AD/LDAP is a legitimate internal target.
    import ipaddress
    import socket
    try:
        infos = socket.getaddrinfo(host, parsed.port or 389, proto=socket.IPPROTO_TCP)
    except Exception:
        return None  # unresolved — let the bind attempt fail normally
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
            return f"Blocked host (resolves to {addr}): {host}"
    return None


def _validate_ldap_filter(f: str) -> str | None:
    import re
    if not f.startswith("(") or not f.endswith(")"):
        return "Filter must be enclosed in parentheses"
    if re.search(r'[;\x00-\x1f]', f):
        return "Filter contains invalid characters"
    return None


def _sync_ldap_generic(config: dict, group_filters: list[str]) -> SyncResult:
    import ldap3
    from ldap3 import ALL, SUBTREE, Connection, Server

    ldap_url = config.get("ldap_url", "").strip()
    bind_dn = config.get("bind_dn", "").strip()
    bind_password = config.get("bind_password", "")
    base_dn = config.get("base_dn", "").strip()
    user_filter = config.get("user_filter", "").strip() or "(objectClass=inetOrgPerson)"
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
        "uid", "mail", "cn", "displayName", "memberOf",
        "nsAccountLock", "dn", "departmentNumber", "title",
        "objectClass",
    ]

    users: list[UserRecord] = []
    errors: list[str] = []

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
        for entry in entry_generator:
            if entry.get("type") != "searchResEntry":
                continue

            attrs = entry.get("attributes", {})
            count += 1

            member_of_raw = _ensure_list(attrs.get("memberOf"))
            group_cns = [_parse_group_cn(dn) for dn in member_of_raw]

            if group_filters_lower:
                matched = any(g.lower() in group_filters_lower for g in group_cns)
                if not matched:
                    continue

            mail = attrs.get("mail", "") or ""
            uid = attrs.get("uid", "") or ""
            display_name = attrs.get("displayName", "") or attrs.get("cn", "") or ""
            department = attrs.get("departmentNumber", "") or ""
            title = attrs.get("title", "") or ""
            dn = attrs.get("dn", "") or entry.get("dn", "")

            # Account lock detection (OpenLDAP/FreeIPA)
            ns_lock = attrs.get("nsAccountLock", "")
            is_locked = str(ns_lock).lower() == "true" if ns_lock else False

            if is_locked:
                type_compte = "desactive"
            elif not mail:
                type_compte = "service"
            else:
                type_compte = "personnel"

            email = mail if mail else uid

            users.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=[],
                groups=group_cns,
                raw_data={
                    "uid": uid,
                    "mail": mail,
                    "cn": attrs.get("cn", ""),
                    "memberOf": group_cns,
                    "dn": dn,
                    "departmentNumber": department,
                    "title": title,
                    "nsAccountLock": is_locked,
                },
            ))

        logger.info("LDAP generic sync: found %d entries, %d users after filtering", count, len(users))

    except Exception as e:
        errors.append(f"LDAP search error: {e}")
        logger.error("LDAP generic search error: %s", e)
    finally:
        conn.unbind()

    return SyncResult(users=users, errors=errors)


def _test_ldap_generic(config: dict) -> dict:
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
            attributes=["dn"],
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


class LdapGenericPlugin(AccessPlugin):
    plugin_type = "ldap_generic"
    label = "LDAP (OpenLDAP / FreeIPA)"
    label_en = "LDAP (OpenLDAP / FreeIPA)"
    config_schema = [
        {"key": "ldap_url", "label": "URL du serveur LDAP", "label_en": "LDAP Server URL", "type": "text", "required": True, "placeholder": "ldaps://ldap.example.com:636"},
        {"key": "bind_dn", "label": "Bind DN", "label_en": "Bind DN", "type": "text", "required": True, "placeholder": "cn=readonly,dc=example,dc=com"},
        {"key": "bind_password", "label": "Mot de passe Bind", "label_en": "Bind Password", "type": "password", "required": True},
        {"key": "base_dn", "label": "Base DN (recherche)", "label_en": "Base DN (search)", "type": "text", "required": True, "placeholder": "dc=example,dc=com"},
        {"key": "user_filter", "label": "Filtre utilisateurs", "label_en": "User filter", "type": "text", "required": False, "placeholder": "(objectClass=inetOrgPerson)"},
        {"key": "use_ssl", "label": "Utiliser SSL/STARTTLS", "label_en": "Use SSL/STARTTLS", "type": "checkbox", "required": False},
    ]
    setup_guide = (
        "1. Créer un compte de service (Bind DN) avec accès en lecture seule :\n"
        "   - OpenLDAP : créer un DN dédié (ex: cn=readonly,dc=example,dc=com)\n"
        "   - FreeIPA : créer un utilisateur système avec rôle \"User Administrator\" en lecture seule\n"
        "2. Configurer les ACL LDAP pour autoriser la lecture des attributs utilisateur :\n"
        "   - uid, mail, cn, displayName, memberOf, nsAccountLock\n"
        "3. Aucun accès en écriture requis\n"
        "4. Utiliser LDAPS (port 636) pour chiffrer la connexion\n"
        "5. Le filtre par défaut est (objectClass=inetOrgPerson)\n"
        "   Pour FreeIPA : (objectClass=person)\n"
        "   Pour exclure les comptes verrouillés : (&(objectClass=inetOrgPerson)(!(nsAccountLock=true)))\n\n"
        "Permissions minimales : lecture seule sur les entrées utilisateur (uid, mail, cn, memberOf)"
    )
    setup_guide_en = (
        "1. Create a service account (Bind DN) with read-only access:\n"
        "   - OpenLDAP: create a dedicated DN (e.g. cn=readonly,dc=example,dc=com)\n"
        "   - FreeIPA: create a system user with read-only \"User Administrator\" role\n"
        "2. Configure LDAP ACLs to allow reading user attributes:\n"
        "   - uid, mail, cn, displayName, memberOf, nsAccountLock\n"
        "3. No write access required\n"
        "4. Use LDAPS (port 636) to encrypt the connection\n"
        "5. Default user filter is (objectClass=inetOrgPerson)\n"
        "   For FreeIPA: (objectClass=person)\n"
        "   To exclude locked accounts: (&(objectClass=inetOrgPerson)(!(nsAccountLock=true)))\n\n"
        "Minimum permissions: read-only on user entries (uid, mail, cn, memberOf)"
    )

    async def test_connection(self, config: dict) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _test_ldap_generic, config)

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync_ldap_generic, config, group_filters)
