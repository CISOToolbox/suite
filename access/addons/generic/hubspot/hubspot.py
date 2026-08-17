from __future__ import annotations

import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

API_BASE = "https://api.hubapi.com"


class HubspotPlugin(AccessPlugin):
    plugin_type = "hubspot"
    label = "HubSpot CRM"
    label_en = "HubSpot CRM"
    config_schema = [
        {"key": "api_key", "label": "Jeton d'accès (Private App)", "label_en": "Access token (Private App)", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans HubSpot > Paramètres > Intégrations > Applications privées\n"
        "2. Créer une nouvelle application privée \"CISO Access Reader\"\n"
        "3. Permissions requises (onglet Portées) :\n"
        "   - crm.objects.contacts.read (lecture contacts)\n"
        "   - settings.users.read (lecture utilisateurs)\n"
        "   - settings.users.teams.read (lecture équipes)\n"
        "4. Aucune permission d'écriture nécessaire\n"
        "5. Copier le jeton d'accès généré\n\n"
        "Permissions minimales : settings.users.read, settings.users.teams.read"
    )
    setup_guide_en = (
        "1. Go to HubSpot > Settings > Integrations > Private Apps\n"
        "2. Create a new private app \"CISO Access Reader\"\n"
        "3. Required scopes (Scopes tab):\n"
        "   - crm.objects.contacts.read (read contacts)\n"
        "   - settings.users.read (read users)\n"
        "   - settings.users.teams.read (read teams)\n"
        "4. No write permissions needed\n"
        "5. Copy the generated access token\n\n"
        "Minimum permissions: settings.users.read, settings.users.teams.read"
    )

    def _headers(self, config: dict) -> dict:
        return {
            "Authorization": f"Bearer {config['api_key']}",
            "Accept": "application/json",
        }

    async def test_connection(self, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{API_BASE}/crm/v3/objects/contacts",
                    params={"limit": "1"},
                    headers=self._headers(config),
                )
                resp.raise_for_status()
            return {"ok": True, "error": "", "details": "Connected to HubSpot account"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        headers = self._headers(config)

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch all users
            resp = await client.get(f"{API_BASE}/settings/v3/users", headers=headers)
            resp.raise_for_status()
            raw_users = resp.json().get("results", [])
            logger.info("HubSpot sync: fetched %d users", len(raw_users))

            # Fetch roles for each user
            user_roles: list[tuple[dict, list[str]]] = []
            for user in raw_users:
                user_id = user.get("id")
                roles: list[str] = []
                try:
                    r = await client.get(
                        f"{API_BASE}/settings/v3/users/{user_id}/roles",
                        headers=headers,
                    )
                    r.raise_for_status()
                    for role in r.json().get("results", []):
                        name = role.get("name") or role.get("id", "")
                        if name:
                            roles.append(name)
                except Exception as e:
                    errors.append(f"roles for user {user_id}: {e}")
                user_roles.append((user, roles))

        # Build filter set (case-insensitive)
        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user, roles in user_roles:
            email = user.get("email", "")
            if not email:
                continue

            first = user.get("firstName", "")
            last = user.get("lastName", "")
            display_name = f"{first} {last}".strip()

            teams: list[str] = []
            for t in user.get("teams", []):
                team_name = t.get("name", "")
                if team_name:
                    teams.append(team_name)

            # Apply group filter on teams
            if filter_set:
                if not any(t.lower() in filter_set for t in teams):
                    continue

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte="personnel",
                roles=roles,
                groups=teams,
                raw_data=user,
            ))

        logger.info("HubSpot sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
