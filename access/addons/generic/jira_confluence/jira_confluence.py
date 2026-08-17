from __future__ import annotations

import base64
import logging

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")


class AtlassianPlugin(AccessPlugin):
    plugin_type = "atlassian"
    label = "Atlassian Cloud (Jira/Confluence)"
    label_en = "Atlassian Cloud (Jira/Confluence)"
    config_schema = [
        {"key": "domain", "label": "Domaine Atlassian", "label_en": "Atlassian Domain", "type": "text", "required": True, "placeholder": "myorg.atlassian.net"},
        {"key": "email", "label": "Email du compte", "label_en": "Account email", "type": "text", "required": True, "placeholder": "admin@example.com"},
        {"key": "api_token", "label": "Jeton API", "label_en": "API Token", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller sur https://id.atlassian.com/manage-profile/security/api-tokens\n"
        "2. Créer un nouveau jeton API nommé \"CISO Access Reader\"\n"
        "3. Le compte doit avoir la permission \"Browse users and groups\" dans Jira\n"
        "4. Pour Confluence, le compte doit être membre du groupe confluence-users\n"
        "5. Aucune permission d'administration requise — lecture seule suffit\n"
        "6. Le domaine est la partie avant .atlassian.net (ex: myorg.atlassian.net)\n\n"
        "Permissions minimales : \"Browse users and groups\" dans Jira, membre de confluence-users"
    )
    setup_guide_en = (
        "1. Go to https://id.atlassian.com/manage-profile/security/api-tokens\n"
        "2. Create a new API token named \"CISO Access Reader\"\n"
        "3. The account must have \"Browse users and groups\" permission in Jira\n"
        "4. For Confluence, the account must be a member of the confluence-users group\n"
        "5. No admin permissions required — read-only is sufficient\n"
        "6. The domain is the part before .atlassian.net (e.g. myorg.atlassian.net)\n\n"
        "Minimum permissions: \"Browse users and groups\" in Jira, confluence-users member"
    )

    def _headers(self, config: dict) -> dict:
        creds = base64.b64encode(f"{config['email']}:{config['api_token']}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    def _base_url(self, config: dict) -> str:
        domain = config["domain"].strip().rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        # The Basic-auth API token is sent to this host: refuse anything
        # that resolves to loopback / metadata / an internal address.
        return validate_connector_base_url(domain)

    async def test_connection(self, config: dict) -> dict:
        try:
            base = self._base_url(config)
            headers = self._headers(config)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/rest/api/3/myself", headers=headers)
                resp.raise_for_status()
                data = resp.json()
            name = data.get("displayName", data.get("emailAddress", ""))
            return {"ok": True, "error": "", "details": f"Connected as: {name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        base = self._base_url(config)
        headers = self._headers(config)

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch Jira users
            raw_users: list[dict] = []
            start = 0
            while True:
                resp = await client.get(
                    f"{base}/rest/api/3/users/search",
                    params={"startAt": str(start), "maxResults": "1000"},
                    headers=headers,
                )
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break
                raw_users.extend(batch)
                if len(batch) < 1000:
                    break
                start += len(batch)

            logger.info("Atlassian sync: fetched %d Jira users", len(raw_users))

            # Fetch Confluence groups and members
            confluence_groups: dict[str, list[str]] = {}  # user_id -> [group_names]
            try:
                grp_resp = await client.get(
                    f"{base}/wiki/rest/api/group",
                    params={"limit": "200"},
                    headers=headers,
                )
                if grp_resp.status_code == 200:
                    groups_data = grp_resp.json().get("results", [])
                    for grp in groups_data:
                        grp_name = grp.get("name", "")
                        try:
                            members_resp = await client.get(
                                f"{base}/wiki/rest/api/group/{grp_name}/member",
                                params={"limit": "200"},
                                headers=headers,
                            )
                            if members_resp.status_code == 200:
                                for m in members_resp.json().get("results", []):
                                    account_id = m.get("accountId", "")
                                    if account_id:
                                        confluence_groups.setdefault(account_id, []).append(grp_name)
                        except Exception as e:
                            errors.append(f"Confluence group members {grp_name}: {e}")
            except Exception as e:
                errors.append(f"Confluence groups: {e}")

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            email = user.get("emailAddress", "")
            account_type = user.get("accountType", "")
            if account_type == "app":
                continue
            if not email:
                continue

            display_name = user.get("displayName", "")
            account_id = user.get("accountId", "")
            active = user.get("active", True)

            groups = confluence_groups.get(account_id, [])

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            type_compte = "personnel" if active else "desactive"
            if account_type == "customer":
                type_compte = "service"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=[],
                groups=groups,
                account_enabled=bool(active),
                raw_data={
                    "accountId": account_id,
                    "accountType": account_type,
                    "active": active,
                },
            ))

        logger.info("Atlassian sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
