from __future__ import annotations

import asyncio
import logging
import re

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

GITHUB_API = "https://api.github.com"
MAX_CONCURRENT = 10


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _parse_link_next(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        match = re.search(r'<([^>]+)>;\s*rel="next"', part)
        if match:
            return match.group(1)
    return None


async def _github_request(
    client: httpx.AsyncClient, url: str, token: str, params: dict | None = None,
) -> httpx.Response:
    headers = _github_headers(token)
    for attempt in range(3):
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
            logger.warning("GitHub 429 rate-limited, retrying in %ds", retry_after)
            await asyncio.sleep(retry_after)
            continue
        resp.raise_for_status()
        return resp
    raise httpx.HTTPStatusError("Rate limited after retries", request=resp.request, response=resp)


async def _github_paginate(
    client: httpx.AsyncClient, url: str, token: str, params: dict | None = None,
) -> list[dict]:
    all_items: list[dict] = []
    params = dict(params or {})
    params.setdefault("per_page", 100)
    next_url: str | None = url
    next_params: dict | None = params
    while next_url:
        resp = await _github_request(client, next_url, token, next_params)
        items = resp.json()
        if isinstance(items, list):
            all_items.extend(items)
        else:
            break
        link_next = _parse_link_next(resp.headers.get("Link"))
        if link_next:
            next_url = link_next
            next_params = None  # params are embedded in the Link URL
        else:
            break
    return all_items


class GitHubOrgPlugin(AccessPlugin):
    plugin_type = "github"
    label = "GitHub"
    label_en = "GitHub"
    config_schema = [
        {"key": "organization", "label": "Organisation GitHub", "label_en": "GitHub Organization", "type": "text", "required": True, "placeholder": "my-org"},
        {"key": "access_token", "label": "Access Token (PAT)", "label_en": "Access Token (PAT)", "type": "password", "required": True},
    ]
    setup_guide = (
        "1. Aller dans GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens\n"
        "2. Créer un token \"ciso-access-reader\" avec :\n"
        "   - Resource owner : sélectionner l'organisation\n"
        "   - Repository access : No repositories (on ne lit pas le code)\n"
        "   - Organization permissions :\n"
        "     - Members : Read-only\n"
        "   - Aucune permission sur les repositories\n"
        "3. Ou utiliser un Classic token avec la portée :\n"
        "   - read:org (lecture des membres et équipes)\n"
        "4. Aucune portée d'écriture (pas de admin:org, write:org, etc.)\n\n"
        "Permissions minimales : Organization Members (Read-only)"
    )
    setup_guide_en = (
        "1. Go to GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens\n"
        "2. Create a token \"ciso-access-reader\" with:\n"
        "   - Resource owner: select the organization\n"
        "   - Repository access: No repositories (no code access)\n"
        "   - Organization permissions:\n"
        "     - Members: Read-only\n"
        "   - No repository permissions\n"
        "3. Or use a Classic token with scope:\n"
        "   - read:org (read org members and teams)\n"
        "4. No write scopes (no admin:org, write:org, etc.)\n\n"
        "Minimum permissions: Organization Members (Read-only)"
    )

    async def test_connection(self, config: dict) -> dict:
        org = config.get("organization", "")
        token = config.get("access_token", "")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await _github_request(client, f"{GITHUB_API}/orgs/{org}", token)
                data = resp.json()
            org_name = data.get("name") or data.get("login", org)
            return {"ok": True, "error": "", "details": f"Organization: {org_name}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        org = config["organization"]
        token = config["access_token"]
        errors: list[str] = []

        async with httpx.AsyncClient(timeout=60) as client:
            # Fetch org members and teams in parallel
            raw_members, raw_teams = await asyncio.gather(
                _github_paginate(client, f"{GITHUB_API}/orgs/{org}/members", token),
                _github_paginate(client, f"{GITHUB_API}/orgs/{org}/teams", token),
            )
            logger.info("GitHub sync: fetched %d members, %d teams", len(raw_members), len(raw_teams))

            sem = asyncio.Semaphore(MAX_CONCURRENT)

            # Fetch org membership role for each member
            async def fetch_membership(member: dict) -> tuple[dict, str]:
                username = member["login"]
                async with sem:
                    try:
                        resp = await _github_request(
                            client, f"{GITHUB_API}/orgs/{org}/memberships/{username}", token,
                        )
                        data = resp.json()
                        role = data.get("role", "member")
                    except Exception as e:
                        errors.append(f"membership for {username}: {e}")
                        role = "member"
                return member, role

            membership_tasks = [fetch_membership(m) for m in raw_members]
            membership_results = await asyncio.gather(*membership_tasks)

            # Build username -> (member, role) map
            user_map: dict[str, tuple[dict, str]] = {}
            for member, role in membership_results:
                user_map[member["login"]] = (member, role)

            # Fetch team members for each team
            team_members_map: dict[str, list[str]] = {}  # username -> [team names]

            async def fetch_team_members(team: dict) -> tuple[str, list[dict]]:
                slug = team["slug"]
                name = team.get("name", slug)
                async with sem:
                    try:
                        members = await _github_paginate(
                            client, f"{GITHUB_API}/orgs/{org}/teams/{slug}/members", token,
                        )
                    except Exception as e:
                        errors.append(f"team members for {name}: {e}")
                        members = []
                return name, members

            team_tasks = [fetch_team_members(t) for t in raw_teams]
            team_results = await asyncio.gather(*team_tasks)

            for team_name, members in team_results:
                for m in members:
                    login = m["login"]
                    team_members_map.setdefault(login, []).append(team_name)

            # Fetch user details (for email) concurrently
            async def fetch_user_detail(username: str) -> tuple[str, dict]:
                async with sem:
                    try:
                        resp = await _github_request(
                            client, f"{GITHUB_API}/users/{username}", token,
                        )
                        return username, resp.json()
                    except Exception as e:
                        errors.append(f"user detail for {username}: {e}")
                        return username, {}

            detail_tasks = [fetch_user_detail(login) for login in user_map]
            detail_results = await asyncio.gather(*detail_tasks)
            user_details: dict[str, dict] = dict(detail_results)

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for login, (member, role) in user_map.items():
            teams = team_members_map.get(login, [])

            if filter_set:
                if not any(t.lower() in filter_set for t in teams):
                    continue

            detail = user_details.get(login, {})
            email = detail.get("email") or f"{login}@users.noreply.github.com"
            display_name = detail.get("name") or login

            user_type = member.get("type", "User")
            type_compte = "service" if user_type == "Bot" else "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=[role],
                groups=teams,
                raw_data={
                    "id": member.get("id"),
                    "login": login,
                    "type": user_type,
                    "site_admin": member.get("site_admin", False),
                    "html_url": member.get("html_url"),
                    "company": detail.get("company"),
                    "blog": detail.get("blog"),
                    "two_factor_authentication": detail.get("two_factor_authentication"),
                    "teams": teams,
                },
            ))

        logger.info("GitHub sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
