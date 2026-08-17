from __future__ import annotations

import asyncio
import logging
from datetime import datetime

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord
from src.plugins._graph_auth import (
    GRAPH_BASE, MAX_CONCURRENT,
    get_graph_token, graph_get, graph_get_all,
)

logger = logging.getLogger("access-backend")


class EntraIdPlugin(AccessPlugin):
    plugin_type = "entra_id"
    label = "Entra ID (Azure AD)"
    label_en = "Entra ID (Azure AD)"
    config_schema = [
        {"key": "tenant_id", "label": "Tenant ID", "label_en": "Tenant ID", "type": "text", "required": True},
        {"key": "client_id", "label": "Client ID", "label_en": "Client ID", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client Secret", "label_en": "Client Secret", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans Azure Portal > Entra ID > Inscriptions d'applications\n"
        "2. Réutiliser l'inscription créée pour M365 ou en créer une nouvelle \"CISO Access - Entra Reader\"\n"
        "3. Aller dans Autorisations d'API > Ajouter les permissions Microsoft Graph (Application) :\n"
        "   - User.Read.All (lecture des utilisateurs)\n"
        "   - Group.Read.All (lecture des groupes et membres)\n"
        "   - Directory.Read.All (rôles d'annuaire)\n"
        "   - Application.Read.All (affectations de rôles applicatifs)\n"
        "   - RoleManagement.Read.Directory (rôles Entra ID)\n"
        "   - AuditLog.Read.All (date de dernière connexion — optionnel)\n"
        "4. Cliquer \"Accorder le consentement administrateur\"\n"
        "5. Aucune permission d'écriture n'est nécessaire\n\n"
        "Dernière connexion : la date de dernière connexion (signInActivity) nécessite "
        "AuditLog.Read.All ET une licence Entra ID P1 ou P2. Sans cela, la synchronisation "
        "fonctionne mais la colonne \"Dernière connexion\" reste vide.\n\n"
        "Différence avec le connecteur M365 : Entra ID se concentre sur la gouvernance des identités "
        "(rôles d'annuaire, affectations applicatives, accès conditionnel) plutôt que sur les licences et boîtes mail.\n\n"
        "Permissions minimales : User.Read.All, Group.Read.All, Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory"
    )
    setup_guide_en = (
        "1. Go to Azure Portal > Entra ID > App registrations\n"
        "2. Reuse the registration created for M365 or create a new one \"CISO Access - Entra Reader\"\n"
        "3. Go to API permissions > Add Microsoft Graph (Application) permissions:\n"
        "   - User.Read.All (read users)\n"
        "   - Group.Read.All (read groups and members)\n"
        "   - Directory.Read.All (directory roles)\n"
        "   - Application.Read.All (app role assignments)\n"
        "   - RoleManagement.Read.Directory (Entra ID roles)\n"
        "   - AuditLog.Read.All (last sign-in date — optional)\n"
        "4. Click \"Grant admin consent\"\n"
        "5. No write permissions needed\n\n"
        "Last sign-in: the last sign-in date (signInActivity) requires "
        "AuditLog.Read.All AND an Entra ID P1 or P2 license. Without it, the sync "
        "still works but the \"Last login\" column stays empty.\n\n"
        "Difference with M365 connector: Entra ID focuses on identity governance "
        "(directory roles, app role assignments, conditional access) rather than licenses and mailboxes.\n\n"
        "Minimum permissions: User.Read.All, Group.Read.All, Directory.Read.All, Application.Read.All, RoleManagement.Read.Directory"
    )

    async def test_connection(self, config: dict) -> dict:
        try:
            token = await get_graph_token(
                config.get("tenant_id", ""),
                config.get("client_id", ""),
                config.get("client_secret", ""),
            )
            async with httpx.AsyncClient(timeout=30) as client:
                data = await graph_get(token, f"{GRAPH_BASE}/organization", client)
            org_name = ""
            orgs = data.get("value", [])
            if orgs:
                org_name = orgs[0].get("displayName", "")
            return {"ok": True, "error": "", "details": f"Connected to tenant: {org_name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        token = await get_graph_token(
            config["tenant_id"], config["client_id"], config["client_secret"],
        )
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch users. signInActivity (last sign-in) needs Entra ID P1/P2 +
            # AuditLog.Read.All; if unavailable, Graph 403s the whole request,
            # so fall back to a query without it (connector still works, no
            # last-login).
            users_select = "id,displayName,mail,userPrincipalName,accountEnabled,userType"
            try:
                raw_users = await graph_get_all(
                    token, f"{GRAPH_BASE}/users?$select={users_select},signInActivity&$top=999", client
                )
            except httpx.HTTPStatusError as e:
                logger.warning("Entra ID: signInActivity unavailable (%s) — fetching users without it", e)
                errors.append(
                    "Dernière connexion indisponible : nécessite Entra ID P1/P2 + permission AuditLog.Read.All"
                )
                raw_users = await graph_get_all(
                    token, f"{GRAPH_BASE}/users?$select={users_select}&$top=999", client
                )
            logger.info("Entra ID sync: fetched %d users", len(raw_users))

            # Fetch all directory roles and their members (bulk — fewer API calls)
            dir_roles_raw = await graph_get_all(token, f"{GRAPH_BASE}/directoryRoles", client)
            role_members: dict[str, list[str]] = {}  # user_id -> [role names]
            sem = asyncio.Semaphore(MAX_CONCURRENT)

            async def fetch_role_members(role: dict) -> None:
                role_name = role.get("displayName", "")
                role_id = role.get("id", "")
                url = f"{GRAPH_BASE}/directoryRoles/{role_id}/members?$select=id"
                async with sem:
                    try:
                        members = await graph_get_all(token, url, client)
                    except Exception as e:
                        errors.append(f"directoryRole members for {role_name}: {e}")
                        return
                for m in members:
                    uid = m.get("id", "")
                    if uid:
                        role_members.setdefault(uid, []).append(role_name)

            await asyncio.gather(*[fetch_role_members(r) for r in dir_roles_raw])
            logger.info("Entra ID sync: fetched %d directory roles", len(dir_roles_raw))

            # Fetch memberOf (groups) + appRoleAssignments per user
            user_groups: dict[str, list[str]] = {}
            user_app_roles: dict[str, list[str]] = {}

            async def fetch_user_details(user: dict) -> None:
                uid = user["id"]
                upn = user.get("userPrincipalName", uid)
                async with sem:
                    # Groups via memberOf
                    try:
                        members = await graph_get_all(
                            token,
                            f"{GRAPH_BASE}/users/{uid}/memberOf?$select=id,displayName",
                            client,
                        )
                        for m in members:
                            if m.get("@odata.type") == "#microsoft.graph.group":
                                user_groups.setdefault(uid, []).append(m.get("displayName", ""))
                    except Exception as e:
                        errors.append(f"memberOf for {upn}: {e}")

                    # App role assignments
                    try:
                        assignments = await graph_get_all(
                            token,
                            f"{GRAPH_BASE}/users/{uid}/appRoleAssignments",
                            client,
                        )
                        for a in assignments:
                            resource = a.get("resourceDisplayName", "")
                            role_id = a.get("appRoleId", "")
                            label = f"{resource}" if role_id == "00000000-0000-0000-0000-000000000000" else f"{resource} ({role_id[:8]})"
                            user_app_roles.setdefault(uid, []).append(label)
                    except Exception as e:
                        errors.append(f"appRoleAssignments for {upn}: {e}")

            await asyncio.gather(*[fetch_user_details(u) for u in raw_users])

        # Build filter set
        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            uid = user["id"]
            groups = user_groups.get(uid, [])

            if filter_set:
                if not any(g.lower() in filter_set for g in groups):
                    continue

            email = user.get("mail") or user.get("userPrincipalName", "")
            if not email:
                continue

            user_type = user.get("userType", "Member")
            account_enabled = user.get("accountEnabled", True)
            type_compte = "service" if user_type == "Guest" or not account_enabled else "personnel"

            # Last sign-in (interactive, then non-interactive fallback) from
            # signInActivity. Absent when the tenant lacks Entra ID P1/P2.
            sia = user.get("signInActivity") or {}
            last_signin_raw = sia.get("lastSignInDateTime") or sia.get("lastNonInteractiveSignInDateTime")
            last_login_at = None
            if last_signin_raw:
                try:
                    last_login_at = datetime.fromisoformat(last_signin_raw.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    last_login_at = None

            # Combine directory roles + app role assignments
            roles = role_members.get(uid, []) + user_app_roles.get(uid, [])

            records.append(UserRecord(
                email=email,
                display_name=user.get("displayName", ""),
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                last_login_at=last_login_at,
                account_enabled=account_enabled,
                raw_data={
                    "id": uid,
                    "userPrincipalName": user.get("userPrincipalName"),
                    "accountEnabled": account_enabled,
                    "active": account_enabled,
                    "userType": user_type,
                    "last_sign_in": last_signin_raw,
                    "directory_roles": role_members.get(uid, []),
                    "app_role_assignments": user_app_roles.get(uid, []),
                },
            ))

        logger.info("Entra ID sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
