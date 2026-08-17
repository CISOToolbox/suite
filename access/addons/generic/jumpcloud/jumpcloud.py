from __future__ import annotations

import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

JUMPCLOUD_API = "https://console.jumpcloud.com"


class JumpCloudPlugin(AccessPlugin):
    plugin_type = "jumpcloud"
    label = "JumpCloud"
    label_en = "JumpCloud"
    config_schema = [
        {"key": "api_key", "label": "Clé API", "label_en": "API Key", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Se connecter à la console d'administration JumpCloud\n"
        "2. Aller dans le menu utilisateur (en haut à droite) > API Settings\n"
        "3. Copier la clé API existante ou en générer une nouvelle\n"
        "4. Pour restreindre les permissions (recommandé) :\n"
        "   - Créer un administrateur avec le rôle \"Read Only\"\n"
        "   - Utiliser la clé API de cet administrateur\n"
        "5. La clé API donne accès en lecture à tous les objets de l'organisation\n\n"
        "Permissions minimales : rôle Read Only dans la console d'administration JumpCloud"
    )
    setup_guide_en = (
        "1. Log in to the JumpCloud admin console\n"
        "2. Go to the user menu (top right) > API Settings\n"
        "3. Copy the existing API key or generate a new one\n"
        "4. To restrict permissions (recommended):\n"
        "   - Create an administrator with the \"Read Only\" role\n"
        "   - Use that administrator's API key\n"
        "5. The API key gives read access to all objects in the organization\n\n"
        "Minimum permissions: Read Only role in the JumpCloud admin console"
    )

    def _headers(self, config: dict) -> dict:
        return {
            "x-api-key": config["api_key"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{JUMPCLOUD_API}/api/v2/organizations",
                    headers=self._headers(config),
                )
                resp.raise_for_status()
                orgs = resp.json()
            org_name = ""
            if isinstance(orgs, list) and orgs:
                org_name = orgs[0].get("displayName", "")
            return {"ok": True, "error": "", "details": f"Connected to JumpCloud org: {org_name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        headers = self._headers(config)

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch users (paginated)
            raw_users: list[dict] = []
            skip = 0
            limit = 100
            while True:
                resp = await client.get(
                    f"{JUMPCLOUD_API}/api/systemusers",
                    headers=headers,
                    params={"skip": str(skip), "limit": str(limit)},
                )
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", [])
                raw_users.extend(results)
                total = data.get("totalCount", 0)
                skip += limit
                if skip >= total or not results:
                    break

            logger.info("JumpCloud sync: fetched %d users", len(raw_users))

            # Fetch user groups
            raw_groups: list[dict] = []
            skip = 0
            while True:
                resp = await client.get(
                    f"{JUMPCLOUD_API}/api/v2/usergroups",
                    headers=headers,
                    params={"skip": str(skip), "limit": str(limit)},
                )
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break
                raw_groups.extend(batch)
                if len(batch) < limit:
                    break
                skip += limit

            # Build group membership: user_id -> [group_names]
            user_groups: dict[str, list[str]] = {}
            for grp in raw_groups:
                grp_id = grp.get("id", "")
                grp_name = grp.get("name", "")
                try:
                    resp = await client.get(
                        f"{JUMPCLOUD_API}/api/v2/usergroups/{grp_id}/members",
                        headers=headers,
                        params={"limit": "100"},
                    )
                    if resp.status_code == 429:
                        import asyncio
                        await asyncio.sleep(2)
                        resp = await client.get(
                            f"{JUMPCLOUD_API}/api/v2/usergroups/{grp_id}/members",
                            headers=headers,
                            params={"limit": "100"},
                        )
                    resp.raise_for_status()
                    for member in resp.json():
                        to_obj = member.get("to", {})
                        user_id = to_obj.get("id", "")
                        if user_id:
                            user_groups.setdefault(user_id, []).append(grp_name)
                except Exception as e:
                    errors.append(f"members of group {grp_name}: {e}")

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            email = user.get("email", "")
            if not email:
                continue

            uid = user.get("_id", user.get("id", ""))
            first = user.get("firstname", "")
            last = user.get("lastname", "")
            display_name = f"{first} {last}".strip()

            groups = user_groups.get(uid, [])

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            state = user.get("state", "")
            suspended = user.get("suspended", False)
            if state == "STAGED" or suspended:
                type_compte = "desactive"
            elif user.get("account_locked"):
                type_compte = "desactive"
            else:
                type_compte = "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=[],
                groups=groups,
                account_enabled=(not suspended and state != "STAGED"),
                raw_data={
                    "id": uid,
                    "username": user.get("username"),
                    "state": state,
                    "suspended": suspended,
                    "mfa_configured": user.get("mfa", {}).get("configured", False),
                    "department": user.get("department"),
                    "jobTitle": user.get("jobTitle"),
                },
            ))

        logger.info("JumpCloud sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
