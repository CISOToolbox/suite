"""Cloud Temple (Shiva) IAM connector for the Access module.

Authenticates with a Personal Access Token pair (client_id + secret),
then lists users + their tenant role assignments from the Shiva IAM API.

Endpoints hit during a sync:
  POST /api/iam/v2/auth/personal_access_token   (login — returns JWT, TTL 5 min)
  GET  /api/iam/v2/users?companyId=<c>          (humans + service accounts)
  GET  /api/iam/v2/roles                        (role catalog → id→name)
  GET  /api/iam/v2/tenants                      (tenants accessible to the PAT)
  GET  /api/iam/v2/assignments/tenant?tenantId=<t>&userId=<u>
                                                (per-user tenant-scoped roles)

The `companyId` and default `tenantId` are extracted from the JWT
claims (`companyId`, `scope.id`) so the operator only has to paste the
PAT pair — no additional IDs required when working within a single
tenant.

Permissions required on the PAT:
  - iam_read (users, roles, tenants, assignments)
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import re
import socket
import urllib.parse

import httpx

from src.plugins.base import AccessPlugin, SyncResult, UserRecord

logger = logging.getLogger("access-backend")

_DEFAULT_BASE = "https://shiva.cloud-temple.com"
_MAX_USERS_FULL_FETCH = 500  # beyond this we bail rather than N+1 storm


def _validate_base_url(url: str) -> str | None:
    """Cloud Temple is a public SaaS — block any SSRF target that
    resolves to a non-public address. Mirrors the asset-module helper
    in asset/src/plugins/base.py (can't import cross-module)."""
    u = (url or "").strip()
    if not re.match(r"^https?://", u, re.IGNORECASE):
        return "Base URL must start with http(s)://"
    parsed = urllib.parse.urlparse(u)
    host = (parsed.hostname or "").lower()
    if not host:
        return "Missing host in URL"
    for b in ("localhost", "metadata.google.internal", "metadata.internal"):
        if host == b or host.endswith("." + b):
            return f"Blocked host: {host}"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return f"DNS resolution failed: {e}"
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved
                or addr.is_unspecified):
            return f"Blocked: {host} resolves to internal IP {addr}"
    return None


def _decode_jwt_claims(token: str) -> dict:
    """Best-effort decode of the JWT payload. Returns {} on any error —
    the token is still used as a Bearer, we just lose the claim hints."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


async def _login(client: httpx.AsyncClient, base: str,
                 client_id: str, secret: str) -> str:
    url = base.rstrip("/") + "/api/iam/v2/auth/personal_access_token"
    resp = await client.post(url, json={"id": client_id, "secret": secret})
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"auth failed (HTTP {resp.status_code})")
    token = resp.text.strip().strip('"')
    if not token or "." not in token:
        raise RuntimeError("auth returned unexpected token payload")
    return token


async def _get(client: httpx.AsyncClient, base: str, path: str,
               token: str, params: dict | None = None) -> list[dict]:
    url = base.rstrip("/") + path
    resp = await client.get(url, params=params or {},
                            headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        logger.warning("Cloud Temple GET %s → HTTP %d", path, resp.status_code)
        return []
    try:
        data = resp.json()
    except Exception:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("data", "items", "results"):
            v = data.get(k)
            if isinstance(v, list):
                return v
    return []


def _classify_type(u: dict) -> str:
    """Cloud Temple User.type: 'user' for humans, 'service' / 'bot' for
    service accounts. We normalise to the Access two-value convention."""
    raw = str(u.get("type") or "").strip().lower()
    if raw in ("service", "serviceaccount", "service_account", "bot", "machine"):
        return "service"
    return "personnel"


class CloudTempleIamPlugin(AccessPlugin):
    plugin_type = "cloudtemple_iam"
    label = "Cloud Temple (Shiva) — IAM"
    label_en = "Cloud Temple (Shiva) — IAM"
    config_schema = [
        {"key": "api_base_url", "label": "URL de l'API",
         "label_en": "API base URL", "type": "text", "required": False,
         "placeholder": _DEFAULT_BASE},
        {"key": "client_id", "label": "Client ID (PAT)",
         "label_en": "Client ID (PAT)", "type": "text", "required": True},
        {"key": "client_secret", "label": "Secret ID (PAT)",
         "label_en": "Secret ID (PAT)", "type": "password", "required": True},
        {"key": "tenant_id", "label": "Tenant ID (optionnel)",
         "label_en": "Tenant ID (optional)", "type": "text", "required": False,
         "placeholder": "Laisser vide pour utiliser le tenant du PAT"},
        {"key": "company_id", "label": "Company ID (optionnel)",
         "label_en": "Company ID (optional)", "type": "text", "required": False,
         "placeholder": "Laisser vide pour utiliser la company du PAT"},
        {"key": "exclude_service_accounts", "label": "Exclure les comptes de service",
         "label_en": "Exclude service accounts", "type": "checkbox", "required": False},
        {"key": "exclude_unverified_email", "label": "Exclure les emails non vérifiés",
         "label_en": "Exclude unverified emails", "type": "checkbox", "required": False},
    ]
    setup_guide = (
        "1. Depuis la console Cloud Temple (https://shiva.cloud-temple.com),\n"
        "   profil → 'Jeton d'accès personnel' → 'Nouveau access token personnel'.\n"
        "2. Noter le Client ID + Secret ID (le secret n'est plus affiché après).\n"
        "3. Permission minimale recommandée : rôle IAM read (lecture users +\n"
        "   roles + tenants + assignments).\n"
        "4. Le connecteur lit :\n"
        "   - /iam/v2/users : annuaire des comptes humains + services\n"
        "   - /iam/v2/roles : catalogue des rôles (id → nom lisible)\n"
        "   - /iam/v2/tenants : tenants accessibles au PAT\n"
        "   - /iam/v2/assignments/tenant : rôles de chaque utilisateur\n"
        "     sur le tenant cible\n"
        "5. Le Company ID et le Tenant ID par défaut sont extraits des\n"
        "   claims du JWT (champs companyId + scope.id). Les laisser vides\n"
        "   pour utiliser la cartographie par défaut du PAT.\n"
        "6. L'API IAM n'expose pas la date de dernière connexion :\n"
        "   last_login_at restera vide pour ce connecteur."
    )
    setup_guide_en = (
        "1. From the Cloud Temple console (https://shiva.cloud-temple.com),\n"
        "   profile → 'Personal access token' → 'New personal access token'.\n"
        "2. Record the Client ID + Secret ID (secret shown only once).\n"
        "3. Minimum permission: an IAM read role covering users + roles +\n"
        "   tenants + assignments.\n"
        "4. The connector reads:\n"
        "   - /iam/v2/users : human + service accounts directory\n"
        "   - /iam/v2/roles : role catalog (id → human label)\n"
        "   - /iam/v2/tenants : tenants visible to the PAT\n"
        "   - /iam/v2/assignments/tenant : per-user tenant-scoped roles\n"
        "5. Company ID and Tenant ID default to the values carried by the\n"
        "   JWT claims (companyId + scope.id). Leave them empty to use\n"
        "   the PAT's implicit scope.\n"
        "6. The IAM API does not expose a last login timestamp: the\n"
        "   last_login_at field stays empty for this connector."
    )

    async def test_connection(self, config: dict) -> dict:
        base = (config.get("api_base_url") or _DEFAULT_BASE).strip()
        err = _validate_base_url(base)
        if err:
            return {"ok": False, "error": err, "details": ""}
        cid = (config.get("client_id") or "").strip()
        sec = config.get("client_secret") or ""
        if not cid or not sec:
            return {"ok": False, "error": "Missing client_id / client_secret", "details": ""}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                token = await _login(client, base, cid, sec)
                claims = _decode_jwt_claims(token)
                scope = claims.get("scope") or {}
                scope_id = scope.get("id") if isinstance(scope, dict) else ""
                company_id = claims.get("companyId") or ""
                # Sanity check: hit /roles (cheap, pure read)
                roles = await _get(client, base, "/api/iam/v2/roles", token)
        except Exception as e:
            logger.exception("Cloud Temple IAM test failed")
            # Never surface the raw exception message — it can carry
            # HTTP response bodies, credentials fragments, etc.
            return {"ok": False, "error": f"{type(e).__name__} (see server logs)",
                    "details": ""}
        return {
            "ok": True, "error": "",
            "details": (f"Auth OK. tenant={scope_id or '?'}, "
                        f"company={company_id or '?'}, {len(roles)} role(s) visible."),
        }

    async def sync(self, config: dict, group_filters: list[str]) -> SyncResult:
        base = (config.get("api_base_url") or _DEFAULT_BASE).strip()
        err = _validate_base_url(base)
        if err:
            return SyncResult(errors=[f"Invalid base URL: {err}"])
        cid = (config.get("client_id") or "").strip()
        sec = config.get("client_secret") or ""
        if not cid or not sec:
            return SyncResult(errors=["Missing client_id / client_secret"])

        exclude_svc = bool(config.get("exclude_service_accounts", False))
        exclude_unverified = bool(config.get("exclude_unverified_email", False))

        users: list[UserRecord] = []
        errors: list[str] = []

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                token = await _login(client, base, cid, sec)
                claims = _decode_jwt_claims(token)
                scope = claims.get("scope") or {}
                default_tenant_id = (scope.get("id") if isinstance(scope, dict)
                                     else "") or ""
                default_company_id = claims.get("companyId") or ""

                tenant_id = (config.get("tenant_id") or default_tenant_id).strip()
                company_id = (config.get("company_id") or default_company_id).strip()
                if not tenant_id:
                    errors.append("tenant_id missing and not present in JWT claims")
                    return SyncResult(errors=errors)

                # Role catalog: id → human label
                roles_raw = await _get(client, base, "/api/iam/v2/roles", token)
                role_label: dict[str, str] = {}
                for r in roles_raw:
                    rid = str(r.get("id") or r.get("ID") or "")
                    rname = str(r.get("name") or r.get("Name") or rid)
                    if rid:
                        role_label[rid] = rname

                # Tenant catalog: id → name (for enrichment)
                tenants_raw = await _get(client, base, "/api/iam/v2/tenants", token)
                tenant_label: dict[str, str] = {}
                for tn in tenants_raw:
                    tid = str(tn.get("id") or tn.get("ID") or "")
                    tname = str(tn.get("name") or tn.get("Name") or tid)
                    if tid:
                        tenant_label[tid] = tname
                current_tenant_name = tenant_label.get(tenant_id, tenant_id)

                # User directory
                params = {"companyId": company_id} if company_id else {}
                users_raw = await _get(client, base, "/api/iam/v2/users",
                                       token, params=params)
                if len(users_raw) > _MAX_USERS_FULL_FETCH:
                    total = len(users_raw)
                    logger.warning(
                        "Cloud Temple IAM: %d users > cap %d — truncating",
                        total, _MAX_USERS_FULL_FETCH)
                    errors.append(
                        f"Directory truncated: {total} users returned, "
                        f"only the first {_MAX_USERS_FULL_FETCH} processed. "
                        f"Use filters or paginate the connector.")
                    users_raw = users_raw[:_MAX_USERS_FULL_FETCH]

                # For each user, fetch tenant-scoped assignments
                semaphore = asyncio.Semaphore(10)

                async def _fetch_user_roles(uid: str) -> list[str]:
                    async with semaphore:
                        assignments = await _get(
                            client, base, "/api/iam/v2/assignments/tenant",
                            token, params={"userId": uid, "tenantId": tenant_id})
                    names: list[str] = []
                    for a in assignments:
                        rid = str(a.get("roleId") or a.get("RoleID") or "")
                        if rid:
                            names.append(role_label.get(rid, rid))
                    return names

                coros = []
                mapped: list[tuple[dict, asyncio.Task]] = []
                for u in users_raw:
                    uid = str(u.get("id") or u.get("ID") or "")
                    if not uid:
                        continue
                    coros.append(_fetch_user_roles(uid))
                    mapped.append((u, None))  # placeholder
                try:
                    results = await asyncio.gather(*coros, return_exceptions=True)
                except Exception as e:
                    errors.append(f"assignments fetch: {type(e).__name__}")
                    results = [[]] * len(mapped)

                for (u, _), res in zip(mapped, results):
                    if isinstance(res, Exception):
                        errors.append(f"user {u.get('id')}: {type(res).__name__}")
                        roles_for_user: list[str] = []
                    else:
                        roles_for_user = res or []

                    email = (u.get("email") or u.get("Email") or "").strip().lower()
                    if not email:
                        continue
                    if exclude_unverified and not bool(u.get("emailVerified",
                                                             u.get("EmailVerified", True))):
                        continue
                    type_compte = _classify_type(u)
                    if exclude_svc and type_compte == "service":
                        continue
                    display = str(u.get("name") or u.get("Name") or "").strip() or email

                    raw_snapshot = {
                        "id": u.get("id") or u.get("ID"),
                        "type": u.get("type") or u.get("Type"),
                        "source": u.get("source") or u.get("Source"),
                        "sourceId": u.get("sourceId") or u.get("SourceID"),
                        "emailVerified": u.get("emailVerified", u.get("EmailVerified")),
                        "tenantId": tenant_id,
                    }
                    users.append(UserRecord(
                        email=email,
                        display_name=display,
                        type_compte=type_compte,
                        roles=roles_for_user,
                        groups=[current_tenant_name] if roles_for_user else [],
                        raw_data=raw_snapshot,
                    ))
        except Exception as e:
            logger.exception("Cloud Temple IAM sync failed")
            errors.append(f"{type(e).__name__} (see server logs)")

        logger.info("Cloud Temple IAM sync: %d user(s), %d error(s)",
                    len(users), len(errors))
        return SyncResult(users=users, errors=errors)
