from __future__ import annotations

import asyncio
import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord
from src.plugins._graph_auth import (
    GRAPH_BASE, MAX_CONCURRENT,
    get_graph_token, graph_get, graph_get_all,
)

logger = logging.getLogger("access-backend")


class M365Plugin(AccessPlugin):
    plugin_type = "m365"
    label = "Microsoft 365"
    label_en = "Microsoft 365"
    config_schema = [
        {"key": "tenant_id", "label": "Tenant ID", "label_en": "Tenant ID", "type": "text", "required": True},
        {"key": "client_id", "label": "Client ID (App Registration)", "label_en": "Client ID (App Registration)", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client Secret", "label_en": "Client Secret", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans Azure Portal > Entra ID > Inscriptions d'applications\n"
        "2. Cliquer \"Nouvelle inscription\" — nommer \"CISO Access - M365 Reader\"\n"
        "3. Type de compte : \"Comptes dans cet annuaire uniquement\"\n"
        "4. Aller dans Certificats et secrets > Nouveau secret client (durée : 24 mois max)\n"
        "5. Noter le Tenant ID, Client ID (vue d'ensemble) et la valeur du secret\n"
        "6. Aller dans Autorisations d'API > Ajouter les permissions Microsoft Graph (Application) :\n"
        "   - User.Read.All (lecture des utilisateurs et licences)\n"
        "   - Group.Read.All (lecture des groupes et membres)\n"
        "   - Directory.Read.All (lecture des rôles et affectations)\n"
        "   - Organization.Read.All (lecture des informations du tenant)\n"
        "7. Cliquer \"Accorder le consentement administrateur\"\n"
        "8. Aucune permission d'écriture n'est nécessaire — le connecteur est en lecture seule\n\n"
        "Permissions minimales : User.Read.All, Group.Read.All, Directory.Read.All, Organization.Read.All"
    )
    setup_guide_en = (
        "1. Go to Azure Portal > Entra ID > App registrations\n"
        "2. Click \"New registration\" — name it \"CISO Access - M365 Reader\"\n"
        "3. Account type: \"Accounts in this organizational directory only\"\n"
        "4. Go to Certificates & secrets > New client secret (max 24 months)\n"
        "5. Note the Tenant ID, Client ID (overview) and the secret value\n"
        "6. Go to API permissions > Add Microsoft Graph (Application) permissions:\n"
        "   - User.Read.All (read users and licenses)\n"
        "   - Group.Read.All (read groups and members)\n"
        "   - Directory.Read.All (read roles and assignments)\n"
        "   - Organization.Read.All (read tenant info)\n"
        "7. Click \"Grant admin consent\"\n"
        "8. No write permissions needed — the connector is read-only\n\n"
        "Minimum permissions: User.Read.All, Group.Read.All, Directory.Read.All, Organization.Read.All"
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
            # Fetch all users with license info
            users_url = (
                f"{GRAPH_BASE}/users"
                "?$select=id,displayName,mail,userPrincipalName,accountEnabled,"
                "userType,assignedLicenses,department,jobTitle"
                "&$top=999"
            )
            raw_users = await graph_get_all(token, users_url, client)
            logger.info("M365 sync: fetched %d users", len(raw_users))

            # Fetch memberOf for each user (groups + directory roles)
            sem = asyncio.Semaphore(MAX_CONCURRENT)

            async def fetch_member_of(user: dict) -> tuple[dict, list[dict]]:
                uid = user["id"]
                url = f"{GRAPH_BASE}/users/{uid}/memberOf?$select=id,displayName"
                async with sem:
                    try:
                        members = await graph_get_all(token, url, client)
                    except Exception as e:
                        errors.append(f"memberOf for {user.get('userPrincipalName', uid)}: {e}")
                        members = []
                return user, members

            tasks = [fetch_member_of(u) for u in raw_users]
            results = await asyncio.gather(*tasks)

        # Build filter set (case-insensitive)
        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user, memberships in results:
            groups: list[str] = []
            roles: list[str] = []
            for m in memberships:
                odata_type = m.get("@odata.type", "")
                name = m.get("displayName", "")
                if odata_type == "#microsoft.graph.group":
                    groups.append(name)
                elif odata_type == "#microsoft.graph.directoryRole":
                    roles.append(name)

            # Apply group filter
            if filter_set:
                if not any(g.lower() in filter_set for g in groups):
                    continue

            email = user.get("mail") or user.get("userPrincipalName", "")
            if not email:
                continue

            user_type = user.get("userType", "Member")
            type_compte = "service" if user_type == "Guest" else "personnel"

            records.append(UserRecord(
                email=email,
                display_name=user.get("displayName", ""),
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                account_enabled=user.get("accountEnabled"),
                raw_data={
                    "id": user.get("id"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "accountEnabled": user.get("accountEnabled"),
                    "userType": user_type,
                    "department": user.get("department"),
                    "jobTitle": user.get("jobTitle"),
                    "assignedLicenses": user.get("assignedLicenses", []),
                },
            ))

        logger.info("M365 sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
