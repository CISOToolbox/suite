from __future__ import annotations

import asyncio
import base64
import logging

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

MAX_CONCURRENT = 10


def _basic_auth_header(pat: str) -> str:
    encoded = base64.b64encode(f":{pat}".encode()).decode()
    return f"Basic {encoded}"


async def _ado_request(
    client: httpx.AsyncClient, url: str, auth_header: str, params: dict | None = None,
) -> httpx.Response:
    for attempt in range(3):
        resp = await client.get(
            url,
            headers={"Authorization": auth_header, "Accept": "application/json"},
            params=params,
        )
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
            logger.warning("Azure DevOps 429 rate-limited, retrying in %ds", retry_after)
            await asyncio.sleep(retry_after)
            continue
        resp.raise_for_status()
        return resp
    raise httpx.HTTPStatusError("Rate limited after retries", request=resp.request, response=resp)


async def _ado_paginate_graph(
    client: httpx.AsyncClient, url: str, auth_header: str,
) -> list[dict]:
    all_items: list[dict] = []
    continuation_token = None
    while True:
        params = {}
        if continuation_token:
            params["continuationToken"] = continuation_token
        resp = await _ado_request(client, url, auth_header, params)
        data = resp.json()
        all_items.extend(data.get("value", []))
        continuation_token = data.get("continuationToken")
        if not continuation_token:
            break
    return all_items


class AzureDevOpsPlugin(AccessPlugin):
    plugin_type = "azure_devops"
    label = "Azure DevOps"
    label_en = "Azure DevOps"
    config_schema = [
        {"key": "organization", "label": "Organisation", "label_en": "Organization", "type": "text", "required": True, "placeholder": "myorg"},
        {"key": "pat", "label": "Personal Access Token", "label_en": "Personal Access Token", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans Azure DevOps > User Settings (icône en haut à droite) > Personal Access Tokens\n"
        "2. Créer un nouveau token \"ciso-access-reader\" avec :\n"
        "   - Organisation : sélectionner l'organisation cible\n"
        "   - Expiration : 1 an max\n"
        "   - Portées (Scopes) :\n"
        "     - Member Entitlement Management : Read\n"
        "     - Graph : Read\n"
        "     - Project and Team : Read\n"
        "3. Aucune portée d'écriture nécessaire\n"
        "4. Copier le token généré (il ne sera plus visible)\n\n"
        "Permissions minimales : Member Entitlement Management (Read), Graph (Read), Project and Team (Read)"
    )
    setup_guide_en = (
        "1. Go to Azure DevOps > User Settings (top-right icon) > Personal Access Tokens\n"
        "2. Create a new token \"ciso-access-reader\" with:\n"
        "   - Organization: select the target organization\n"
        "   - Expiration: 1 year max\n"
        "   - Scopes:\n"
        "     - Member Entitlement Management: Read\n"
        "     - Graph: Read\n"
        "     - Project and Team: Read\n"
        "3. No write scopes needed\n"
        "4. Copy the generated token (it won't be visible again)\n\n"
        "Minimum permissions: Member Entitlement Management (Read), Graph (Read), Project and Team (Read)"
    )

    async def test_connection(self, config: dict) -> dict:
        org = config.get("organization", "")
        pat = config.get("pat", "")
        auth = _basic_auth_header(pat)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await _ado_request(
                    client,
                    f"https://dev.azure.com/{org}/_apis/projects",
                    auth,
                    params={"api-version": "7.1", "$top": "1"},
                )
                data = resp.json()
            count = data.get("count", 0)
            return {"ok": True, "error": "", "details": f"Organization: {org} ({count} project(s))"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        org = config["organization"]
        auth = _basic_auth_header(config["pat"])
        vssps_base = f"https://vssps.dev.azure.com/{org}"
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch all users and groups in parallel
            raw_users, raw_groups = await asyncio.gather(
                _ado_paginate_graph(
                    client,
                    f"{vssps_base}/_apis/graph/users?api-version=7.1-preview.1",
                    auth,
                ),
                _ado_paginate_graph(
                    client,
                    f"{vssps_base}/_apis/graph/groups?api-version=7.1-preview.1",
                    auth,
                ),
            )
            logger.info("Azure DevOps sync: fetched %d users, %d groups", len(raw_users), len(raw_groups))

            # Build group descriptor -> displayName map
            group_map: dict[str, str] = {}
            for g in raw_groups:
                desc = g.get("descriptor", "")
                if desc:
                    group_map[desc] = g.get("displayName", "")

            # Fetch memberships for each user
            sem = asyncio.Semaphore(MAX_CONCURRENT)

            async def fetch_memberships(user: dict) -> tuple[dict, list[str]]:
                descriptor = user.get("descriptor", "")
                if not descriptor:
                    return user, []
                url = f"{vssps_base}/_apis/graph/memberships/{descriptor}?api-version=7.1-preview.1&direction=up"
                async with sem:
                    try:
                        resp = await _ado_request(client, url, auth)
                        data = resp.json()
                        membership_descriptors = [
                            m.get("containerDescriptor", "")
                            for m in data.get("value", [])
                        ]
                        group_names = [
                            group_map[d] for d in membership_descriptors if d in group_map
                        ]
                    except Exception as e:
                        errors.append(f"memberships for {user.get('displayName', descriptor)}: {e}")
                        group_names = []
                return user, group_names

            tasks = [fetch_memberships(u) for u in raw_users]
            results = await asyncio.gather(*tasks)

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user, groups in results:
            if filter_set:
                if not any(g.lower() in filter_set for g in groups):
                    continue

            email = user.get("mailAddress") or user.get("principalName") or ""
            if not email:
                continue

            origin = user.get("origin", "")
            subject_kind = user.get("subjectKind", "")
            type_compte = "service" if origin == "vsts" or subject_kind == "service" else "personnel"

            records.append(UserRecord(
                email=email,
                display_name=user.get("displayName", ""),
                type_compte=type_compte,
                roles=[],
                groups=groups,
                raw_data={
                    "descriptor": user.get("descriptor"),
                    "origin": origin,
                    "originId": user.get("originId"),
                    "subjectKind": subject_kind,
                    "domain": user.get("domain"),
                    "directoryAlias": user.get("directoryAlias"),
                    "metaType": user.get("metaType"),
                },
            ))

        logger.info("Azure DevOps sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
