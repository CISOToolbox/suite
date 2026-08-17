from __future__ import annotations

import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

REGIONS = {
    "NA": "api.pingone.com",
    "EU": "api.pingone.eu",
    "AP": "api.pingone.asia",
    "CA": "api.pingone.ca",
}

AUTH_REGIONS = {
    "NA": "auth.pingone.com",
    "EU": "auth.pingone.eu",
    "AP": "auth.pingone.asia",
    "CA": "auth.pingone.ca",
}


async def _get_pingone_token(config: dict) -> tuple[str, str]:
    """OAuth2 client_credentials -> (access_token, api_base)."""
    region = config.get("region", "NA").upper()
    auth_host = AUTH_REGIONS.get(region, AUTH_REGIONS["NA"])
    api_host = REGIONS.get(region, REGIONS["NA"])
    env_id = config["environment_id"]

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"https://{auth_host}/{env_id}/as/token",
            data={"grant_type": "client_credentials"},
            auth=(config["client_id"], config["client_secret"]),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        token = resp.json()["access_token"]
    return token, f"https://{api_host}"


class PingOnePlugin(AccessPlugin):
    plugin_type = "pingone"
    label = "PingOne (Ping Identity)"
    label_en = "PingOne (Ping Identity)"
    config_schema = [
        {"key": "environment_id", "label": "Environment ID", "label_en": "Environment ID", "type": "text", "required": True},
        {"key": "client_id", "label": "Client ID (Worker App)", "label_en": "Client ID (Worker App)", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client Secret", "label_en": "Client Secret", "type": "password", "required": True},
        {"key": "region", "label": "Région (NA, EU, AP, CA)", "label_en": "Region (NA, EU, AP, CA)", "type": "text", "required": True, "placeholder": "EU"},
    ]
    setup_guide = (
        "1. Se connecter à la console d'administration PingOne\n"
        "2. Aller dans Applications > Applications > Ajouter une application\n"
        "3. Sélectionner \"Worker\" comme type d'application\n"
        "4. Nommer l'application \"CISO Access Reader\"\n"
        "5. Dans l'onglet Rôles, attribuer le rôle \"Identity Data Read Only\"\n"
        "   pour l'environnement cible\n"
        "6. Activer l'application et noter le Client ID et Client Secret\n"
        "7. L'Environment ID est visible dans Settings > Environment > Properties\n"
        "8. Choisir la région correspondant à votre instance :\n"
        "   - NA : Amérique du Nord\n"
        "   - EU : Europe\n"
        "   - AP : Asie-Pacifique\n"
        "   - CA : Canada\n\n"
        "Permissions minimales : rôle \"Identity Data Read Only\" (aucune écriture)"
    )
    setup_guide_en = (
        "1. Log in to the PingOne admin console\n"
        "2. Go to Applications > Applications > Add Application\n"
        "3. Select \"Worker\" as the application type\n"
        "4. Name the application \"CISO Access Reader\"\n"
        "5. In the Roles tab, assign the \"Identity Data Read Only\" role\n"
        "   for the target environment\n"
        "6. Enable the application and note the Client ID and Client Secret\n"
        "7. The Environment ID is visible in Settings > Environment > Properties\n"
        "8. Choose the region matching your instance:\n"
        "   - NA: North America\n"
        "   - EU: Europe\n"
        "   - AP: Asia-Pacific\n"
        "   - CA: Canada\n\n"
        "Minimum permissions: \"Identity Data Read Only\" role (no write access)"
    )

    async def test_connection(self, config: dict) -> dict:
        try:
            token, api_base = await _get_pingone_token(config)
            env_id = config["environment_id"]
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{api_base}/v1/environments/{env_id}", headers=headers)
                resp.raise_for_status()
                data = resp.json()
            env_name = data.get("name", "")
            return {"ok": True, "error": "", "details": f"Connected to PingOne environment: {env_name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        token, api_base = await _get_pingone_token(config)
        env_id = config["environment_id"]
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=60) as client:
            # Paginate users
            raw_users: list[dict] = []
            url: str | None = f"{api_base}/v1/environments/{env_id}/users?limit=100"
            while url:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                data = resp.json()
                embedded = data.get("_embedded", {})
                raw_users.extend(embedded.get("users", []))
                # HAL pagination
                next_link = data.get("_links", {}).get("next", {}).get("href")
                url = next_link if next_link else None

            logger.info("PingOne sync: fetched %d users", len(raw_users))

            # Fetch groups
            raw_groups: list[dict] = []
            url = f"{api_base}/v1/environments/{env_id}/groups?limit=100"
            while url:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                data = resp.json()
                raw_groups.extend(data.get("_embedded", {}).get("groups", []))
                next_link = data.get("_links", {}).get("next", {}).get("href")
                url = next_link if next_link else None

            # Build group membership: user_id -> [group_names]
            user_groups: dict[str, list[str]] = {}
            for grp in raw_groups:
                grp_id = grp.get("id", "")
                grp_name = grp.get("name", "")
                try:
                    members_url: str | None = f"{api_base}/v1/environments/{env_id}/users?filter=memberOfGroups[id eq \"{grp_id}\"]&limit=100"
                    while members_url:
                        r = await client.get(members_url, headers=headers)
                        if r.status_code == 429:
                            import asyncio
                            await asyncio.sleep(2)
                            continue
                        r.raise_for_status()
                        mdata = r.json()
                        for u in mdata.get("_embedded", {}).get("users", []):
                            uid = u.get("id", "")
                            if uid:
                                user_groups.setdefault(uid, []).append(grp_name)
                        members_url = mdata.get("_links", {}).get("next", {}).get("href")
                except Exception as e:
                    errors.append(f"members of group {grp_name}: {e}")

            # Fetch role assignments per user
            user_roles: dict[str, list[str]] = {}
            for user in raw_users:
                uid = user.get("id", "")
                try:
                    r = await client.get(
                        f"{api_base}/v1/environments/{env_id}/users/{uid}/roleAssignments",
                        headers=headers,
                    )
                    if r.status_code == 200:
                        for ra in r.json().get("_embedded", {}).get("roleAssignments", []):
                            role_id = ra.get("role", {}).get("id", "")
                            role_name = ra.get("role", {}).get("name", role_id)
                            if role_name:
                                user_roles.setdefault(uid, []).append(role_name)
                except Exception as e:
                    errors.append(f"roles for user {uid}: {e}")

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            email_obj = user.get("email", {})
            email = email_obj if isinstance(email_obj, str) else email_obj.get("address", "") if isinstance(email_obj, dict) else ""
            if not email:
                continue

            uid = user.get("id", "")
            name = user.get("name", {})
            if isinstance(name, dict):
                display_name = f"{name.get('given', '')} {name.get('family', '')}".strip()
            else:
                display_name = str(name)

            groups = user_groups.get(uid, [])
            roles = user_roles.get(uid, [])

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            status = user.get("status", "")
            enabled = user.get("enabled", True)
            if not enabled or status == "DISABLED":
                type_compte = "desactive"
            else:
                type_compte = "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                raw_data={
                    "id": uid,
                    "status": status,
                    "enabled": enabled,
                    "population": user.get("population", {}).get("id", ""),
                    "lastSignOn": user.get("lastSignOn", {}).get("at", ""),
                },
            ))

        logger.info("PingOne sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
