from __future__ import annotations

import base64
import logging

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")


class ServiceNowPlugin(AccessPlugin):
    plugin_type = "servicenow"
    label = "ServiceNow"
    label_en = "ServiceNow"
    config_schema = [
        {"key": "instance", "label": "Instance ServiceNow", "label_en": "ServiceNow Instance", "type": "text", "required": True, "placeholder": "myorg.service-now.com"},
        {"key": "username", "label": "Nom d'utilisateur", "label_en": "Username", "type": "text", "required": True},
        {"key": "password", "label": "Mot de passe", "label_en": "Password", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Créer un utilisateur d'intégration dans ServiceNow (ex: svc-ciso-access)\n"
        "2. Attribuer le rôle \"itil\" (lecture des utilisateurs et groupes)\n"
        "   ou créer un rôle personnalisé en lecture seule :\n"
        "   - Accès en lecture à sys_user\n"
        "   - Accès en lecture à sys_user_group\n"
        "   - Accès en lecture à sys_user_grmember\n"
        "3. Aucun rôle d'administration requis\n"
        "4. L'instance est le sous-domaine de service-now.com (ex: myorg.service-now.com)\n"
        "5. Activer l'accès API REST pour cet utilisateur si ce n'est pas fait par défaut\n\n"
        "Permissions minimales : rôle itil ou rôle personnalisé avec lecture seule sur sys_user et sys_user_grmember"
    )
    setup_guide_en = (
        "1. Create an integration user in ServiceNow (e.g. svc-ciso-access)\n"
        "2. Assign the \"itil\" role (read users and groups)\n"
        "   or create a custom read-only role:\n"
        "   - Read access to sys_user\n"
        "   - Read access to sys_user_group\n"
        "   - Read access to sys_user_grmember\n"
        "3. No admin role required\n"
        "4. The instance is the subdomain of service-now.com (e.g. myorg.service-now.com)\n"
        "5. Enable REST API access for this user if not enabled by default\n\n"
        "Minimum permissions: itil role or custom role with read-only access to sys_user and sys_user_grmember"
    )

    def _headers(self, config: dict) -> dict:
        creds = base64.b64encode(f"{config['username']}:{config['password']}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    def _base_url(self, config: dict) -> str:
        # The API token is sent to whatever this resolves to, so the
        # assembled URL is vetted here rather than at each call site —
        # "ServiceNow instance" is free-form, not a fixed SaaS endpoint.
        instance = config.get("instance", "").strip().rstrip("/")
        if not instance.startswith("https://"):
            instance = f"https://{instance}"
        return validate_connector_base_url(instance)

    async def test_connection(self, config: dict) -> dict:
        try:
            base = self._base_url(config)
            headers = self._headers(config)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{base}/api/now/table/sys_user",
                    params={"sysparm_limit": "1"},
                    headers=headers,
                )
                resp.raise_for_status()
            return {"ok": True, "error": "", "details": f"Connected to ServiceNow: {config['instance']}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        base = self._base_url(config)
        headers = self._headers(config)

        user_fields = "sys_id,user_name,email,name,active,department,title,locked_out"

        async with httpx.AsyncClient(timeout=60) as client:
            # Paginate users
            raw_users: list[dict] = []
            offset = 0
            limit = 100
            while True:
                resp = await client.get(
                    f"{base}/api/now/table/sys_user",
                    params={
                        "sysparm_fields": user_fields,
                        "sysparm_limit": str(limit),
                        "sysparm_offset": str(offset),
                    },
                    headers=headers,
                )
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                batch = resp.json().get("result", [])
                raw_users.extend(batch)
                if len(batch) < limit:
                    break
                offset += limit

            logger.info("ServiceNow sync: fetched %d users", len(raw_users))

            # Fetch group memberships via sys_user_grmember
            user_groups: dict[str, list[str]] = {}  # sys_id -> [group_names]
            offset = 0
            while True:
                resp = await client.get(
                    f"{base}/api/now/table/sys_user_grmember",
                    params={
                        "sysparm_fields": "user.sys_id,group.name",
                        "sysparm_limit": str(limit),
                        "sysparm_offset": str(offset),
                        "sysparm_display_value": "true",
                    },
                    headers=headers,
                )
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                batch = resp.json().get("result", [])
                for m in batch:
                    user_sid = m.get("user.sys_id", "")
                    group_name = m.get("group.name", "")
                    if user_sid and group_name:
                        user_groups.setdefault(user_sid, []).append(group_name)
                if len(batch) < limit:
                    break
                offset += limit

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            email = user.get("email", "")
            if not email:
                continue

            sys_id = user.get("sys_id", "")
            groups = user_groups.get(sys_id, [])

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            active = user.get("active", "true")
            locked = user.get("locked_out", "false")
            if active == "false" or locked == "true":
                type_compte = "desactive"
            else:
                type_compte = "personnel"

            records.append(UserRecord(
                email=email,
                display_name=user.get("name", ""),
                type_compte=type_compte,
                roles=[],
                groups=groups,
                account_enabled=(active != "false" and locked != "true"),
                raw_data={
                    "sys_id": sys_id,
                    "user_name": user.get("user_name"),
                    "active": active,
                    "locked_out": locked,
                    "department": user.get("department"),
                    "title": user.get("title"),
                },
            ))

        logger.info("ServiceNow sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
