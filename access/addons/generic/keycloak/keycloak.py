from __future__ import annotations

import asyncio
import logging

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")

MAX_CONCURRENT = 10


class KeycloakPlugin(AccessPlugin):
    plugin_type = "keycloak"
    label = "Keycloak"
    label_en = "Keycloak"
    config_schema = [
        {"key": "base_url", "label": "URL de base", "label_en": "Base URL", "type": "text", "required": True, "placeholder": "https://keycloak.example.com"},
        {"key": "realm", "label": "Realm", "label_en": "Realm", "type": "text", "required": True},
        {"key": "client_id", "label": "Client ID", "label_en": "Client ID", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client Secret", "label_en": "Client Secret", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans Keycloak Admin Console > realm cible > Clients\n"
        "2. Créer un nouveau client \"ciso-access-reader\" avec :\n"
        "   - Client authentication : ON\n"
        "   - Authorization : OFF\n"
        "   - Authentication flow : cocher uniquement \"Service accounts roles\"\n"
        "3. Aller dans l'onglet \"Service account roles\"\n"
        "4. Assigner les rôles realm suivants :\n"
        "   - view-users (lecture des utilisateurs)\n"
        "   - view-realm (lecture du realm)\n"
        "   - query-users (recherche d'utilisateurs)\n"
        "   - query-groups (recherche de groupes)\n"
        "5. Ne PAS assigner manage-users, manage-realm ou admin\n"
        "6. Copier le Client ID et le Client Secret (onglet Credentials)\n\n"
        "Permissions minimales : view-users, view-realm, query-users, query-groups"
    )
    setup_guide_en = (
        "1. Go to Keycloak Admin Console > target realm > Clients\n"
        "2. Create a new client \"ciso-access-reader\" with:\n"
        "   - Client authentication: ON\n"
        "   - Authorization: OFF\n"
        "   - Authentication flow: check only \"Service accounts roles\"\n"
        "3. Go to the \"Service account roles\" tab\n"
        "4. Assign the following realm roles:\n"
        "   - view-users (read users)\n"
        "   - view-realm (read realm)\n"
        "   - query-users (search users)\n"
        "   - query-groups (search groups)\n"
        "5. Do NOT assign manage-users, manage-realm or admin\n"
        "6. Copy the Client ID and Client Secret (Credentials tab)\n\n"
        "Minimum permissions: view-users, view-realm, query-users, query-groups"
    )

    def _base_url(self, config: dict) -> str:
        """Validated base URL. The client secret is POSTed to this host, so
        an unchecked value is a credential-exfiltration / SSRF primitive."""
        return validate_connector_base_url(config.get("base_url", ""))

    async def _get_token(self, config: dict) -> str:
        base_url = self._base_url(config)
        realm = config["realm"]
        token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
            })
            resp.raise_for_status()
            return resp.json()["access_token"]

    def _admin_url(self, config: dict) -> str:
        base_url = self._base_url(config)
        return f"{base_url}/admin/realms/{config['realm']}"

    async def test_connection(self, config: dict) -> dict:
        try:
            token = await self._get_token(config)
            admin_url = self._admin_url(config)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(admin_url, headers={"Authorization": f"Bearer {token}"})
                resp.raise_for_status()
                realm_info = resp.json()
            realm_name = realm_info.get("displayName") or realm_info.get("realm", "")
            return {"ok": True, "error": "", "details": f"Connected to realm: {realm_name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        token = await self._get_token(config)
        admin_url = self._admin_url(config)
        errors: list[str] = []
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(timeout=60, headers=headers) as client:
            # Fetch users (paginated)
            raw_users: list[dict] = []
            first = 0
            page_size = 500
            while True:
                resp = await client.get(f"{admin_url}/users", params={"max": page_size, "first": first})
                resp.raise_for_status()
                page = resp.json()
                if not page:
                    break
                raw_users.extend(page)
                if len(page) < page_size:
                    break
                first += page_size

            logger.info("Keycloak sync: fetched %d users", len(raw_users))

            # Fetch roles and groups per user
            user_roles: dict[str, list[str]] = {}
            user_groups: dict[str, list[str]] = {}

            async def fetch_user_details(user: dict) -> None:
                uid = user["id"]
                username = user.get("username", uid)

                async with sem:
                    # Role mappings
                    try:
                        resp = await client.get(f"{admin_url}/users/{uid}/role-mappings")
                        resp.raise_for_status()
                        mappings = resp.json()
                        roles: list[str] = []
                        # Realm roles
                        for r in mappings.get("realmMappings", []):
                            roles.append(r.get("name", ""))
                        # Client roles
                        for client_id, client_roles in mappings.get("clientMappings", {}).items():
                            for r in client_roles.get("mappings", []):
                                roles.append(f"{client_id}/{r.get('name', '')}")
                        user_roles[uid] = roles
                    except Exception as e:
                        errors.append(f"role-mappings for {username}: {e}")

                    # Groups
                    try:
                        resp = await client.get(f"{admin_url}/users/{uid}/groups")
                        resp.raise_for_status()
                        groups_data = resp.json()
                        user_groups[uid] = [g.get("path", g.get("name", "")) for g in groups_data]
                    except Exception as e:
                        errors.append(f"groups for {username}: {e}")

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

            email = user.get("email", "")
            if not email:
                continue

            first_name = user.get("firstName", "")
            last_name = user.get("lastName", "")
            display_name = f"{first_name} {last_name}".strip() or user.get("username", "")

            is_service = bool(user.get("serviceAccountClientId"))
            type_compte = "service" if is_service else "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=user_roles.get(uid, []),
                groups=groups,
                raw_data={
                    "id": uid,
                    "username": user.get("username"),
                    "enabled": user.get("enabled"),
                    "serviceAccountClientId": user.get("serviceAccountClientId"),
                    "realm_roles": [r for r in user_roles.get(uid, []) if "/" not in r],
                    "client_roles": [r for r in user_roles.get(uid, []) if "/" in r],
                    "groups": groups,
                },
            ))

        logger.info("Keycloak sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
