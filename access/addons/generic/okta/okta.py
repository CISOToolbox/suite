from __future__ import annotations

import logging

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")


class OktaPlugin(AccessPlugin):
    plugin_type = "okta"
    label = "Okta"
    label_en = "Okta"
    config_schema = [
        {"key": "domain", "label": "Domaine Okta", "label_en": "Okta Domain", "type": "text", "required": True, "placeholder": "dev-123456.okta.com"},
        {"key": "api_token", "label": "Jeton API (SSWS)", "label_en": "API Token (SSWS)", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Se connecter à la console d'administration Okta\n"
        "2. Aller dans Security > API > Tokens\n"
        "3. Créer un nouveau jeton nommé \"CISO Access Reader\"\n"
        "4. Le compte qui crée le jeton doit avoir le rôle \"Read-Only Administrator\"\n"
        "   - Aller dans Security > Administrators > Add Administrator\n"
        "   - Sélectionner le rôle \"Read-Only Administrator\"\n"
        "5. Copier le jeton généré (il ne sera plus affiché)\n"
        "6. Le domaine est visible dans l'URL de la console (ex: dev-123456.okta.com)\n\n"
        "Permissions minimales : rôle Read-Only Administrator (lecture seule, aucune modification possible)"
    )
    setup_guide_en = (
        "1. Log in to the Okta admin console\n"
        "2. Go to Security > API > Tokens\n"
        "3. Create a new token named \"CISO Access Reader\"\n"
        "4. The account creating the token must have the \"Read-Only Administrator\" role\n"
        "   - Go to Security > Administrators > Add Administrator\n"
        "   - Select the \"Read-Only Administrator\" role\n"
        "5. Copy the generated token (it won't be shown again)\n"
        "6. The domain is visible in the console URL (e.g. dev-123456.okta.com)\n\n"
        "Minimum permissions: Read-Only Administrator role (read-only, no modifications possible)"
    )

    def _headers(self, config: dict) -> dict:
        return {
            "Authorization": f"SSWS {config['api_token']}",
            "Accept": "application/json",
        }

    def _base_url(self, config: dict) -> str:
        # The API token is sent to whatever this resolves to, so the
        # assembled URL is vetted here rather than at each call site —
        # "Okta domain" is free-form, not a fixed SaaS endpoint.
        domain = config.get("domain", "").strip().rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return validate_connector_base_url(domain)

    async def test_connection(self, config: dict) -> dict:
        try:
            base = self._base_url(config)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/api/v1/org", headers=self._headers(config))
                resp.raise_for_status()
                data = resp.json()
            org_name = data.get("companyName", data.get("name", ""))
            return {"ok": True, "error": "", "details": f"Connected to Okta org: {org_name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def _paginate(self, client: httpx.AsyncClient, url: str, headers: dict) -> list[dict]:
        results: list[dict] = []
        while url:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("retry-after", "2"))
                import asyncio
                await asyncio.sleep(retry_after)
                continue
            resp.raise_for_status()
            results.extend(resp.json())
            url = ""
            link = resp.headers.get("link", "")
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    break
        return results

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        base = self._base_url(config)
        headers = self._headers(config)

        async with httpx.AsyncClient(timeout=60) as client:
            raw_users = await self._paginate(client, f"{base}/api/v1/users?limit=200", headers)
            logger.info("Okta sync: fetched %d users", len(raw_users))

            user_details: list[tuple[dict, list[str], list[str]]] = []
            for user in raw_users:
                uid = user.get("id", "")
                groups: list[str] = []
                roles: list[str] = []

                try:
                    grp_data = await self._paginate(client, f"{base}/api/v1/users/{uid}/groups", headers)
                    for g in grp_data:
                        name = g.get("profile", {}).get("name", "")
                        if name:
                            groups.append(name)
                except Exception as e:
                    errors.append(f"groups for user {uid}: {e}")

                try:
                    role_data = await self._paginate(client, f"{base}/api/v1/users/{uid}/roles", headers)
                    for r in role_data:
                        label = r.get("label") or r.get("type", "")
                        if label:
                            roles.append(label)
                except Exception as e:
                    errors.append(f"roles for user {uid}: {e}")

                user_details.append((user, groups, roles))

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user, groups, roles in user_details:
            profile = user.get("profile", {})
            email = profile.get("email", "")
            if not email:
                continue

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            first = profile.get("firstName", "")
            last = profile.get("lastName", "")
            display_name = f"{first} {last}".strip()

            status = user.get("status", "")
            if status in ("DEPROVISIONED", "SUSPENDED"):
                type_compte = "desactive"
            elif not profile.get("email"):
                type_compte = "service"
            else:
                type_compte = "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                account_enabled=(status not in ("SUSPENDED", "DEPROVISIONED")) if status else None,
                raw_data={
                    "id": user.get("id"),
                    "status": status,
                    "login": profile.get("login"),
                    "department": profile.get("department"),
                    "title": profile.get("title"),
                },
            ))

        logger.info("Okta sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
