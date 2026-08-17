from __future__ import annotations

import logging

import httpx

from src.plugins.base import (
    AccessPlugin, SyncResult, UserRecord, validate_connector_base_url,
)

logger = logging.getLogger("access-backend")


async def _get_sf_token(config: dict) -> tuple[str, str]:
    """OAuth2 password flow -> (access_token, instance_url)."""
    # This POST carries client_secret, username and password, so the host has
    # to be vetted before we reach out — an unvalidated instance_url turns the
    # connector into a credential-exfiltration channel.
    instance = validate_connector_base_url(config.get("instance_url", ""))
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{instance}/services/oauth2/token",
            data={
                "grant_type": "password",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "username": config["username"],
                "password": config["password"] + config.get("security_token", ""),
            },
        )
        resp.raise_for_status()
        data = resp.json()
    # Salesforce answers with the instance_url to use from here on, and every
    # later call attaches the bearer token to it. Left as-is it is a second hop
    # to a host the response chose, so it gets the same check as the first.
    return data["access_token"], validate_connector_base_url(data["instance_url"])


class SalesforcePlugin(AccessPlugin):
    plugin_type = "salesforce"
    label = "Salesforce"
    label_en = "Salesforce"
    config_schema = [
        {"key": "instance_url", "label": "URL de l'instance", "label_en": "Instance URL", "type": "text", "required": True, "placeholder": "https://myorg.my.salesforce.com"},
        {"key": "client_id", "label": "Client ID (Connected App)", "label_en": "Client ID (Connected App)", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client Secret", "label_en": "Client Secret", "type": "password", "required": True},
        {"key": "username", "label": "Nom d'utilisateur", "label_en": "Username", "type": "text", "required": True, "placeholder": "integration@example.com"},
        {"key": "password", "label": "Mot de passe", "label_en": "Password", "type": "password", "required": True},
        {"key": "security_token", "label": "Jeton de sécurité", "label_en": "Security Token", "type": "password", "required": False, "placeholder": "(optionnel si IP de confiance)"},
    ]
    setup_guide = (
        "1. Aller dans Setup > Apps > App Manager > New Connected App\n"
        "2. Nommer l'application \"CISO Access Reader\"\n"
        "3. Activer OAuth Settings, callback URL: https://login.salesforce.com/services/oauth2/callback\n"
        "4. Portée OAuth : \"api\" (accès API complet)\n"
        "5. Créer un utilisateur d'intégration avec le profil \"Read Only\" ou un profil personnalisé :\n"
        "   - Permission \"View Setup and Configuration\"\n"
        "   - Permission \"API Enabled\"\n"
        "   - Aucune permission d'écriture\n"
        "6. Le jeton de sécurité est envoyé par email lors de la réinitialisation du mot de passe\n"
        "   (non requis si l'IP du serveur est dans les IP de confiance)\n\n"
        "Permissions minimales : profil Read Only + API Enabled, portée OAuth \"api\""
    )
    setup_guide_en = (
        "1. Go to Setup > Apps > App Manager > New Connected App\n"
        "2. Name the app \"CISO Access Reader\"\n"
        "3. Enable OAuth Settings, callback URL: https://login.salesforce.com/services/oauth2/callback\n"
        "4. OAuth scope: \"api\" (full API access)\n"
        "5. Create an integration user with \"Read Only\" profile or a custom profile:\n"
        "   - Permission \"View Setup and Configuration\"\n"
        "   - Permission \"API Enabled\"\n"
        "   - No write permissions\n"
        "6. The security token is emailed when the password is reset\n"
        "   (not required if the server IP is in Trusted IP Ranges)\n\n"
        "Minimum permissions: Read Only profile + API Enabled, OAuth scope \"api\""
    )

    async def test_connection(self, config: dict) -> dict:
        try:
            token, instance_url = await _get_sf_token(config)
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{instance_url}/services/data/v60.0/sobjects/User/describe",
                    headers=headers,
                )
                resp.raise_for_status()
            return {"ok": True, "error": "", "details": f"Connected to Salesforce: {instance_url}"}
        except Exception as e:
            return {"ok": False, "error": str(e), "details": ""}

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        errors: list[str] = []
        token, instance_url = await _get_sf_token(config)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        soql = (
            "SELECT Id, Name, Email, Username, IsActive, "
            "Profile.Name, UserRole.Name, Department, Title "
            "FROM User"
        )

        raw_users: list[dict] = []
        url: str | None = f"{instance_url}/services/data/v60.0/query?q={soql}"

        async with httpx.AsyncClient(timeout=60) as client:
            while url:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    import asyncio
                    await asyncio.sleep(2)
                    continue
                resp.raise_for_status()
                data = resp.json()
                raw_users.extend(data.get("records", []))
                next_url = data.get("nextRecordsUrl")
                url = f"{instance_url}{next_url}" if next_url else None

        logger.info("Salesforce sync: fetched %d users", len(raw_users))

        filter_set = {g.lower() for g in group_filters} if group_filters else set()

        records: list[UserRecord] = []
        for user in raw_users:
            email = user.get("Email", "")
            if not email:
                continue

            profile_name = ""
            profile = user.get("Profile")
            if profile and isinstance(profile, dict):
                profile_name = profile.get("Name", "")

            role_name = ""
            role = user.get("UserRole")
            if role and isinstance(role, dict):
                role_name = role.get("Name", "")

            roles = [r for r in [profile_name, role_name] if r]
            groups = [profile_name] if profile_name else []

            if filter_set and not any(g.lower() in filter_set for g in groups + roles):
                continue

            is_active = user.get("IsActive", True)
            type_compte = "personnel" if is_active else "desactive"

            records.append(UserRecord(
                email=email,
                display_name=user.get("Name", ""),
                type_compte=type_compte,
                roles=roles,
                groups=groups,
                raw_data={
                    "id": user.get("Id"),
                    "username": user.get("Username"),
                    "isActive": is_active,
                    "profile": profile_name,
                    "role": role_name,
                    "department": user.get("Department"),
                    "title": user.get("Title"),
                },
            ))

        logger.info("Salesforce sync: %d users after filters (%d errors)", len(records), len(errors))
        return SyncResult(users=records, errors=errors)
