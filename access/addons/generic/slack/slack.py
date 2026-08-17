from __future__ import annotations

import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

SLACK_API = "https://slack.com/api"


class SlackPlugin(AccessPlugin):
    plugin_type = "slack"
    label = "Slack"
    label_en = "Slack"
    config_schema = [
        {"key": "bot_token", "label": "Bot Token (xoxb-...)", "label_en": "Bot Token (xoxb-...)", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller sur https://api.slack.com/apps et créer une nouvelle application\n"
        "2. Nommer l'application \"CISO Access Reader\"\n"
        "3. Aller dans OAuth & Permissions > Bot Token Scopes et ajouter :\n"
        "   - users:read (lecture des utilisateurs)\n"
        "   - users:read.email (lecture des emails)\n"
        "   - usergroups:read (lecture des groupes d'utilisateurs)\n"
        "4. Installer l'application dans le workspace\n"
        "5. Copier le Bot User OAuth Token (commence par xoxb-)\n"
        "6. Aucune permission d'écriture nécessaire\n\n"
        "Permissions minimales : users:read, users:read.email, usergroups:read"
    )
    setup_guide_en = (
        "1. Go to https://api.slack.com/apps and create a new app\n"
        "2. Name the app \"CISO Access Reader\"\n"
        "3. Go to OAuth & Permissions > Bot Token Scopes and add:\n"
        "   - users:read (read users)\n"
        "   - users:read.email (read emails)\n"
        "   - usergroups:read (read user groups)\n"
        "4. Install the app to the workspace\n"
        "5. Copy the Bot User OAuth Token (starts with xoxb-)\n"
        "6. No write permissions needed\n\n"
        "Minimum permissions: users:read, users:read.email, usergroups:read"
    )

    def _headers(self, config: dict) -> dict:
        return {
            "Authorization": f"Bearer {config['bot_token']}",
            "Accept": "application/json",
        }

    async def test_connection(self, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{SLACK_API}/auth.test", headers=self._headers(config))
                resp.raise_for_status()
                data = resp.json()
            if not data.get("ok"):
                return {"ok": False, "error": data.get("error", "Unknown error"), "details": ""}
            team = data.get("team", "")
            return {"ok": True, "error": "", "details": f"Connected to Slack workspace: {team}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def _paginate_slack(self, client: httpx.AsyncClient, url: str, headers: dict, params: dict, key: str) -> list[dict]:
        results: list[dict] = []
        cursor = None
        while True:
            p = dict(params)
            if cursor:
                p["cursor"] = cursor
            resp = await client.get(url, headers=headers, params=p)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("retry-after", "5"))
                import asyncio
                await asyncio.sleep(retry_after)
                continue
            resp.raise_for_status()
            data = resp.json()
            if not data.get("ok"):
                raise RuntimeError(data.get("error", "Slack API error"))
            results.extend(data.get(key, []))
            cursor = data.get("response_metadata", {}).get("next_cursor", "")
            if not cursor:
                break
        return results

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        headers = self._headers(config)

        async with httpx.AsyncClient(timeout=60) as client:
            raw_users = await self._paginate_slack(
                client, f"{SLACK_API}/users.list", headers,
                {"limit": "200"}, "members",
            )
            logger.info("Slack sync: fetched %d users", len(raw_users))

            # Fetch user groups and their members
            user_group_map: dict[str, list[str]] = {}  # user_id -> [group_names]
            try:
                resp = await client.get(
                    f"{SLACK_API}/usergroups.list",
                    headers=headers,
                    params={"include_users": "true"},
                )
                resp.raise_for_status()
                ug_data = resp.json()
                if ug_data.get("ok"):
                    for ug in ug_data.get("usergroups", []):
                        ug_name = ug.get("name", ug.get("handle", ""))
                        for uid in ug.get("users", []):
                            user_group_map.setdefault(uid, []).append(ug_name)
            except Exception as e:
                errors.append(f"usergroups: {e}")

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            if user.get("is_bot") or user.get("id") == "USLACKBOT":
                continue

            profile = user.get("profile", {})
            email = profile.get("email", "")
            if not email:
                continue

            uid = user.get("id", "")
            display_name = profile.get("real_name", "") or profile.get("display_name", "")
            groups = user_group_map.get(uid, [])

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            deleted = user.get("deleted", False)
            is_restricted = user.get("is_restricted", False)
            is_ultra_restricted = user.get("is_ultra_restricted", False)

            if deleted:
                type_compte = "desactive"
            elif is_restricted or is_ultra_restricted:
                type_compte = "invite"
            else:
                type_compte = "personnel"

            roles: list[str] = []
            if user.get("is_admin"):
                roles.append("admin")
            if user.get("is_owner"):
                roles.append("owner")
            if user.get("is_primary_owner"):
                roles.append("primary_owner")

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                raw_data={
                    "id": uid,
                    "deleted": deleted,
                    "is_admin": user.get("is_admin"),
                    "is_owner": user.get("is_owner"),
                    "is_restricted": is_restricted,
                    "is_ultra_restricted": is_ultra_restricted,
                    "title": profile.get("title"),
                },
            ))

        logger.info("Slack sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
