from __future__ import annotations

import json
import logging
import time

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

ADMIN_API = "https://admin.googleapis.com/admin/directory/v1"
SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
]


def _build_jwt(service_account: dict, admin_email: str) -> str:
    """Build a signed JWT for Google service account with domain-wide delegation."""
    import jwt

    now = int(time.time())
    payload = {
        "iss": service_account["client_email"],
        "sub": admin_email,
        "scope": " ".join(SCOPES),
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }
    return jwt.encode(payload, service_account["private_key"], algorithm="RS256")


async def _get_access_token(service_account: dict, admin_email: str) -> str:
    signed_jwt = _build_jwt(service_account, admin_email)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": signed_jwt,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


class GoogleWorkspacePlugin(AccessPlugin):
    plugin_type = "google_workspace"
    label = "Google Workspace"
    label_en = "Google Workspace"
    config_schema = [
        {"key": "service_account_json", "label": "Clé JSON du compte de service", "label_en": "Service Account JSON Key", "type": "textarea", "required": True, "placeholder": '{"type": "service_account", ...}'},
        {"key": "admin_email", "label": "Email administrateur délégué", "label_en": "Delegated admin email", "type": "text", "required": True, "placeholder": "admin@example.com"},
        {"key": "domain", "label": "Domaine", "label_en": "Domain", "type": "text", "required": True, "placeholder": "example.com"},
    ]
    setup_guide = (
        "1. Aller dans Google Cloud Console > IAM & Admin > Comptes de service\n"
        "2. Créer un compte de service \"ciso-access-reader\"\n"
        "3. Créer une clé JSON pour ce compte de service\n"
        "4. Aller dans Google Admin Console > Sécurité > Contrôle des API > Délégation au niveau du domaine\n"
        "5. Ajouter le client_id du compte de service avec les portées :\n"
        "   - https://www.googleapis.com/auth/admin.directory.user.readonly\n"
        "   - https://www.googleapis.com/auth/admin.directory.group.readonly\n"
        "6. L'email administrateur doit être un super-admin ou avoir le rôle \"Lecteur\" dans l'organisation\n"
        "7. Coller le contenu JSON complet de la clé dans le champ ci-dessus\n\n"
        "Permissions minimales : portées en lecture seule (user.readonly, group.readonly), délégation au niveau du domaine"
    )
    setup_guide_en = (
        "1. Go to Google Cloud Console > IAM & Admin > Service Accounts\n"
        "2. Create a service account \"ciso-access-reader\"\n"
        "3. Create a JSON key for this service account\n"
        "4. Go to Google Admin Console > Security > API Controls > Domain-wide Delegation\n"
        "5. Add the service account client_id with scopes:\n"
        "   - https://www.googleapis.com/auth/admin.directory.user.readonly\n"
        "   - https://www.googleapis.com/auth/admin.directory.group.readonly\n"
        "6. The admin email must be a super-admin or have the \"Reader\" role in the organization\n"
        "7. Paste the full JSON key content in the field above\n\n"
        "Minimum permissions: read-only scopes (user.readonly, group.readonly), domain-wide delegation"
    )

    def _parse_sa(self, config: dict) -> dict:
        raw = config.get("service_account_json", "")
        if isinstance(raw, str):
            return json.loads(raw)
        return raw

    async def test_connection(self, config: dict) -> dict:
        try:
            sa = self._parse_sa(config)
            token = await _get_access_token(sa, config["admin_email"])
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{ADMIN_API}/users",
                    params={"maxResults": "1", "domain": config["domain"]},
                    headers=headers,
                )
                resp.raise_for_status()
            return {"ok": True, "error": "", "details": f"Connected to Google Workspace domain: {config['domain']}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def _paginate_google(self, client: httpx.AsyncClient, url: str, headers: dict, params: dict, key: str) -> list[dict]:
        results: list[dict] = []
        page_token = None
        while True:
            p = dict(params)
            if page_token:
                p["pageToken"] = page_token
            resp = await client.get(url, headers=headers, params=p)
            if resp.status_code == 429:
                import asyncio
                await asyncio.sleep(2)
                continue
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get(key, []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return results

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        sa = self._parse_sa(config)
        token = await _get_access_token(sa, config["admin_email"])
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        domain = config["domain"]

        async with httpx.AsyncClient(timeout=60) as client:
            raw_users = await self._paginate_google(
                client, f"{ADMIN_API}/users", headers,
                {"domain": domain, "maxResults": "500", "projection": "full"},
                "users",
            )
            logger.info("Google Workspace sync: fetched %d users", len(raw_users))

            # Fetch groups
            raw_groups = await self._paginate_google(
                client, f"{ADMIN_API}/groups", headers,
                {"domain": domain, "maxResults": "200"},
                "groups",
            )

            # Build group membership map: user_email -> [group_names]
            user_groups: dict[str, list[str]] = {}
            for grp in raw_groups:
                grp_email = grp.get("email", "")
                grp_name = grp.get("name", grp_email)
                try:
                    members = await self._paginate_google(
                        client, f"{ADMIN_API}/groups/{grp_email}/members", headers,
                        {"maxResults": "200"},
                        "members",
                    )
                    for m in members:
                        m_email = m.get("email", "").lower()
                        if m_email:
                            user_groups.setdefault(m_email, []).append(grp_name)
                except Exception as e:
                    errors.append(f"members of group {grp_name}: {e}")

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            email = user.get("primaryEmail", "")
            if not email:
                continue

            groups = user_groups.get(email.lower(), [])

            if filter_set and not any(g.lower() in filter_set for g in groups):
                continue

            full_name = user.get("name", {})
            display_name = full_name.get("fullName", "")

            suspended = user.get("suspended", False)
            archived = user.get("archived", False)
            if suspended or archived:
                type_compte = "desactive"
            else:
                type_compte = "personnel"

            records.append(UserRecord(
                email=email,
                display_name=display_name,
                type_compte=type_compte,
                roles=[],
                groups=groups,
                account_enabled=(not (suspended or archived)),
                raw_data={
                    "id": user.get("id"),
                    "orgUnitPath": user.get("orgUnitPath"),
                    "isAdmin": user.get("isAdmin"),
                    "suspended": suspended,
                    "archived": archived,
                    "lastLoginTime": user.get("lastLoginTime"),
                },
            ))

        logger.info("Google Workspace sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
