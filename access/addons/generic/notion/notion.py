from __future__ import annotations

import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

API_BASE = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"


class NotionPlugin(AccessPlugin):
    plugin_type = "notion"
    label = "Notion"
    label_en = "Notion"
    config_schema = [
        {"key": "api_key", "label": "Jeton d'intégration", "label_en": "Integration token", "type": "password", "required": True},
        {"key": "workspace_id", "label": "Workspace ID (optionnel)", "label_en": "Workspace ID (optional)", "type": "text", "required": False},
    ]
    setup_guide = (
        "1. Aller dans Notion > Paramètres > Connexions > Développer ou gérer les intégrations\n"
        "2. Créer une nouvelle intégration interne \"CISO Access Reader\"\n"
        "3. Capacités requises :\n"
        "   - Lire le contenu (Read content)\n"
        "   - Lire les informations utilisateur (Read user information)\n"
        "4. Aucune capacité d'écriture nécessaire\n"
        "5. Copier le jeton d'intégration (commence par ntn_)\n"
        "6. L'intégration a automatiquement accès aux membres du workspace\n\n"
        "Permissions minimales : Read user information uniquement"
    )
    setup_guide_en = (
        "1. Go to Notion > Settings > Connections > Develop or manage integrations\n"
        "2. Create a new internal integration \"CISO Access Reader\"\n"
        "3. Required capabilities:\n"
        "   - Read content\n"
        "   - Read user information\n"
        "4. No write capabilities needed\n"
        "5. Copy the integration token (starts with ntn_)\n"
        "6. The integration automatically has access to workspace members\n\n"
        "Minimum permissions: Read user information only"
    )

    def _headers(self, config: dict) -> dict:
        return {
            "Authorization": f"Bearer {config['api_key']}",
            "Notion-Version": NOTION_VERSION,
            "Accept": "application/json",
        }

    async def test_connection(self, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{API_BASE}/users",
                    headers=self._headers(config),
                )
                resp.raise_for_status()
            return {"ok": True, "error": "", "details": "Connected to Notion workspace"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        headers = self._headers(config)

        raw_users: list[dict] = []
        async with httpx.AsyncClient(timeout=60) as client:
            # Paginated fetch of all workspace members
            start_cursor = None
            while True:
                params = {}
                if start_cursor:
                    params["start_cursor"] = start_cursor

                resp = await client.get(
                    f"{API_BASE}/users",
                    headers=headers,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                raw_users.extend(data.get("results", []))

                if not data.get("has_more"):
                    break
                start_cursor = data.get("next_cursor")

        logger.info("Notion sync: fetched %d users", len(raw_users))

        records: list[UserRecord] = []
        for user in raw_users:
            user_type = user.get("type", "")

            # Extract email
            email = ""
            if user_type == "person":
                email = user.get("person", {}).get("email", "")
            elif user_type == "bot":
                bot_owner = user.get("bot", {}).get("owner", {})
                if bot_owner.get("type") == "user":
                    email = bot_owner.get("user", {}).get("person", {}).get("email", "")

            if not email:
                continue

            display_name = user.get("name", "")
            type_compte = "service" if user_type == "bot" else "personnel"

            # Determine role from owner field if present
            bot_info = user.get("bot", {})
            owner = bot_info.get("owner", {}) if bot_info else {}
            is_workspace_owner = owner.get("type") == "workspace"
            roles = ["owner"] if is_workspace_owner else ["member"]

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=roles,
                groups=[],
                raw_data=user,
            ))

        logger.info("Notion sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
