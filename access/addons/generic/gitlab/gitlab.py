from __future__ import annotations

import asyncio
import logging

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")

GITLAB_ACCESS_LEVELS = {
    10: "Guest",
    20: "Reporter",
    30: "Developer",
    40: "Maintainer",
    50: "Owner",
}

MAX_CONCURRENT = 10


async def _gitlab_request(
    client: httpx.AsyncClient, url: str, token: str, params: dict | None = None,
) -> httpx.Response:
    for attempt in range(3):
        resp = await client.get(
            url, headers={"PRIVATE-TOKEN": token}, params=params,
        )
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
            logger.warning("GitLab 429 rate-limited, retrying in %ds", retry_after)
            await asyncio.sleep(retry_after)
            continue
        resp.raise_for_status()
        return resp
    raise httpx.HTTPStatusError("Rate limited after retries", request=resp.request, response=resp)


async def _gitlab_paginate(
    client: httpx.AsyncClient, url: str, token: str, params: dict | None = None,
) -> list[dict]:
    all_items: list[dict] = []
    page = 1
    params = dict(params or {})
    params["per_page"] = 100
    while True:
        params["page"] = page
        resp = await _gitlab_request(client, url, token, params)
        items = resp.json()
        if not items:
            break
        all_items.extend(items)
        total_pages = int(resp.headers.get("X-Total-Pages", 1))
        if page >= total_pages:
            break
        page += 1
    return all_items


class GitLabPlugin(AccessPlugin):
    plugin_type = "gitlab"
    label = "GitLab"
    label_en = "GitLab"
    config_schema = [
        {"key": "base_url", "label": "URL GitLab", "label_en": "GitLab URL", "type": "text", "required": True, "placeholder": "https://gitlab.example.com"},
        {"key": "access_token", "label": "Access Token", "label_en": "Access Token", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans GitLab > Préférences > Access Tokens (admin) ou Group > Settings > Access Tokens\n"
        "2. Créer un token \"ciso-access-reader\" avec les portées :\n"
        "   - read_api (lecture de l'API)\n"
        "   - read_user (lecture des profils utilisateur)\n"
        "3. Pour un GitLab auto-hébergé : utiliser un token Admin pour lister tous les utilisateurs\n"
        "4. Pour gitlab.com : utiliser un Group Access Token pour lister les membres du groupe\n"
        "5. Aucune portée d'écriture (pas de api, write_repository, etc.)\n"
        "6. Définir une date d'expiration (1 an max recommandé)\n\n"
        "Permissions minimales : read_api, read_user"
    )
    setup_guide_en = (
        "1. Go to GitLab > Preferences > Access Tokens (admin) or Group > Settings > Access Tokens\n"
        "2. Create a token \"ciso-access-reader\" with scopes:\n"
        "   - read_api (API read access)\n"
        "   - read_user (read user profiles)\n"
        "3. For self-hosted GitLab: use an Admin token to list all users\n"
        "4. For gitlab.com: use a Group Access Token to list group members\n"
        "5. No write scopes (no api, write_repository, etc.)\n"
        "6. Set an expiration date (1 year max recommended)\n\n"
        "Minimum permissions: read_api, read_user"
    )

    async def test_connection(self, config: dict) -> dict:
        token = config.get("access_token", "")
        try:
            # PAT is sent to this host — validate before reaching out.
            base_url = validate_connector_base_url(config.get("base_url", ""))
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await _gitlab_request(client, f"{base_url}/api/v4/version", token)
                data = resp.json()
            version = data.get("version", "unknown")
            return {"ok": True, "error": "", "details": f"GitLab {version}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        base_url = validate_connector_base_url(config.get("base_url", ""))
        token = config["access_token"]
        api = f"{base_url}/api/v4"
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch all users
            raw_users = await _gitlab_paginate(client, f"{api}/users", token)
            logger.info("GitLab sync: fetched %d users", len(raw_users))

            # Fetch memberships for each user
            sem = asyncio.Semaphore(MAX_CONCURRENT)

            async def fetch_memberships(user: dict) -> tuple[dict, list[dict]]:
                uid = user["id"]
                async with sem:
                    try:
                        memberships = await _gitlab_paginate(
                            client, f"{api}/users/{uid}/memberships", token,
                        )
                    except Exception as e:
                        errors.append(f"memberships for {user.get('username', uid)}: {e}")
                        memberships = []
                return user, memberships

            tasks = [fetch_memberships(u) for u in raw_users]
            results = await asyncio.gather(*tasks)

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user, memberships in results:
            groups: list[str] = []
            roles: set[str] = set()
            for m in memberships:
                source_type = m.get("source_type", "")
                source_name = m.get("source_name", "")
                source_full = m.get("source_full_name", source_name)
                access_level = m.get("access_level", 0)
                role_name = GITLAB_ACCESS_LEVELS.get(access_level, f"Level {access_level}")
                roles.add(role_name)
                if source_type in ("Namespace", "Project"):
                    groups.append(source_full)

            if filter_set:
                if not any(g.lower() in filter_set for g in groups):
                    continue

            email = user.get("email") or user.get("public_email") or ""
            if not email:
                continue

            state = user.get("state", "active")
            is_bot = user.get("bot", False)
            type_compte = "service" if is_bot or state == "blocked" else "personnel"

            records.append(UserRecord(
                email=email,
                display_name=user.get("name", ""),
                type_compte=type_compte,
                roles=sorted(roles),
                groups=groups,
                account_enabled=(state == "active"),
                raw_data={
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "state": state,
                    "bot": is_bot,
                    "is_admin": user.get("is_admin", False),
                    "two_factor_enabled": user.get("two_factor_enabled"),
                    "memberships": memberships,
                },
            ))

        logger.info("GitLab sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
