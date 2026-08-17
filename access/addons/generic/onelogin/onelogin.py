from __future__ import annotations

import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

REGIONS = {"us": "api.us.onelogin.com", "eu": "api.eu.onelogin.com"}


async def _get_onelogin_token(config: dict) -> tuple[str, str]:
    """OAuth2 client_credentials -> (access_token, api_base)."""
    region = config.get("region", "us").lower()
    api_host = REGIONS.get(region, REGIONS["us"])
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"https://{api_host}/auth/oauth2/v2/token",
            headers={"Content-Type": "application/json"},
            json={
                "grant_type": "client_credentials",
            },
            auth=(config["client_id"], config["client_secret"]),
        )
        resp.raise_for_status()
        token = resp.json()["access_token"]
    return token, f"https://{api_host}"


class OneLoginPlugin(AccessPlugin):
    plugin_type = "onelogin"
    label = "OneLogin"
    label_en = "OneLogin"
    config_schema = [
        {"key": "region", "label": "Région (us ou eu)", "label_en": "Region (us or eu)", "type": "text", "required": True, "placeholder": "us"},
        {"key": "client_id", "label": "Client ID", "label_en": "Client ID", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client Secret", "label_en": "Client Secret", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Se connecter à la console d'administration OneLogin\n"
        "2. Aller dans Developers > API Credentials\n"
        "3. Créer de nouvelles credentials nommées \"CISO Access Reader\"\n"
        "4. Sélectionner les permissions :\n"
        "   - \"Read Users\" (lecture des utilisateurs)\n"
        "   - \"Read All\" (lecture des rôles et groupes)\n"
        "5. Aucune permission d'écriture requise\n"
        "6. Choisir la région correspondant à votre instance :\n"
        "   - us : instances hébergées aux USA\n"
        "   - eu : instances hébergées en Europe\n\n"
        "Permissions minimales : Read Users + Read All (aucune écriture)"
    )
    setup_guide_en = (
        "1. Log in to the OneLogin admin console\n"
        "2. Go to Developers > API Credentials\n"
        "3. Create new credentials named \"CISO Access Reader\"\n"
        "4. Select permissions:\n"
        "   - \"Read Users\" (read users)\n"
        "   - \"Read All\" (read roles and groups)\n"
        "5. No write permissions required\n"
        "6. Choose the region matching your instance:\n"
        "   - us: instances hosted in the USA\n"
        "   - eu: instances hosted in Europe\n\n"
        "Minimum permissions: Read Users + Read All (no write access)"
    )

    async def test_connection(self, config: dict) -> dict:
        try:
            token, api_base = await _get_onelogin_token(config)
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{api_base}/api/2/users", params={"limit": "1"}, headers=headers)
                resp.raise_for_status()
            return {"ok": True, "error": "", "details": f"Connected to OneLogin ({config.get('region', 'us').upper()} region)"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        token, api_base = await _get_onelogin_token(config)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch all roles for mapping
            roles_map: dict[int, str] = {}
            try:
                resp = await client.get(f"{api_base}/api/2/roles", headers=headers)
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    resp = await client.get(f"{api_base}/api/2/roles", headers=headers)
                resp.raise_for_status()
                for role in resp.json():
                    roles_map[role.get("id")] = role.get("name", "")
            except Exception as e:
                errors.append(f"roles: {e}")

            # Paginate users
            raw_users: list[dict] = []
            cursor: str | None = None
            while True:
                params: dict = {"limit": "50"}
                if cursor:
                    params["after_cursor"] = cursor
                resp = await client.get(f"{api_base}/api/2/users", headers=headers, params=params)
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break
                raw_users.extend(batch)
                cursor = resp.headers.get("after-cursor", "")
                if not cursor:
                    break

            logger.info("OneLogin sync: fetched %d users", len(raw_users))

            # Fetch roles per user
            user_roles: list[tuple[dict, list[str]]] = []
            for user in raw_users:
                uid = user.get("id")
                roles: list[str] = []
                role_ids = user.get("role_ids", [])
                if role_ids:
                    for rid in role_ids:
                        name = roles_map.get(rid)
                        if name:
                            roles.append(name)
                        else:
                            try:
                                r = await client.get(f"{api_base}/api/2/roles/{rid}", headers=headers)
                                if r.status_code == 200:
                                    rname = r.json().get("name", str(rid))
                                    roles.append(rname)
                                    roles_map[rid] = rname
                            except Exception as e:
                                errors.append(f"role {rid} for user {uid}: {e}")
                user_roles.append((user, roles))

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user, roles in user_roles:
            email = user.get("email", "")
            if not email:
                continue

            first = user.get("firstname", "")
            last = user.get("lastname", "")
            display_name = f"{first} {last}".strip()

            groups = [user.get("group_id_name", "")] if user.get("group_id_name") else []

            if filter_set and not any(g.lower() in filter_set for g in groups + roles):
                continue

            status = user.get("status", 1)
            # OneLogin status: 0=unactivated, 1=active, 2=suspended, 3=locked, 4=password_expired, 5=awaiting_password_reset
            if status in (2, 3):
                type_compte = "desactive"
            elif status == 0:
                type_compte = "service"
            else:
                type_compte = "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                raw_data={
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "status": status,
                    "department": user.get("department"),
                    "title": user.get("title"),
                    "last_login": user.get("last_login"),
                },
            ))

        logger.info("OneLogin sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
