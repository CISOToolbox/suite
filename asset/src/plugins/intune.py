"""Microsoft Intune (Endpoint Manager) asset connector.

Authenticates against Microsoft Entra ID with an app-only (client
credentials) flow, then pulls the managed devices from Microsoft Graph
(`/deviceManagement/managedDevices`) and maps them to Asset records.

App registration (Entra ID):
  - Register an application, add a client secret.
  - API permission (Application, not Delegated):
        DeviceManagementManagedDevices.Read.All
    then grant admin consent.
  - The connector needs: tenant_id, client_id, client_secret.

Endpoints hit during a sync:
  POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
       (client_credentials — returns an access token, ~1h lifetime)
  GET  https://graph.microsoft.com/v1.0/deviceManagement/managedDevices
       (paginated via @odata.nextLink)

Intune's managedDevices surface does not expose a device IP address, so
`ip_address` is left empty (see AssetRecord: empty fields are preserved
on re-sync and never overwrite a manual edit).
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from src.plugins.base import (
    AssetPlugin, AssetRecord, SyncResult,
    strip_domain as _strip_domain,
)

logger = logging.getLogger("asset-backend")

_REQ_TIMEOUT = 30
_LOGIN_BASE = "https://login.microsoftonline.com"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_PAGE_SIZE = 100
_MAX_PAGES = 200  # hard cap (~20k devices) to avoid runaway pagination
_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects.

    `urlopen` follows 3xx automatically and re-sends the request headers —
    including `Authorization: Bearer <graph-token>` — to the new location.
    A 302 towards an internal host or 169.254.169.254 would therefore leak
    the token. Returning None makes urllib raise the 3xx as an HTTPError,
    which the caller reports as a status.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Module-level opener: same handler chain as `urlopen`, minus redirects.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _http(method: str, url: str, *, token: str = "", data: bytes | None = None,
          content_type: str = "") -> tuple[int, Any, str]:
    """urllib helper. Returns (status, parsed_json_or_None, raw_text)."""
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if content_type:
        headers["Content-Type"] = content_type
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=_REQ_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        status = e.code
    except urllib.error.URLError as e:
        return -1, None, f"URLError: {e.reason}"
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = None
    return status, parsed, raw


def _login(tenant_id: str, client_id: str, secret: str) -> str:
    url = f"{_LOGIN_BASE}/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "scope": _GRAPH_SCOPE,
    }).encode("utf-8")
    status, parsed, raw = _http(
        "POST", url, data=body,
        content_type="application/x-www-form-urlencoded")
    if status != 200 or not isinstance(parsed, dict):
        # Surface Entra's error code (e.g. invalid_client) without the secret.
        err = ""
        if isinstance(parsed, dict):
            err = str(parsed.get("error") or "")
        raise RuntimeError(f"auth failed (HTTP {status}{': ' + err if err else ''})")
    token = str(parsed.get("access_token") or "")
    if not token:
        raise RuntimeError("auth returned no access_token")
    return token


def _classify_device_type(os_name: str, device_type: str) -> str:
    low = (os_name or "").lower() + " " + (device_type or "").lower()
    if any(k in low for k in ("ios", "ipad", "iphone", "android", "windowsphone",
                              "windowsmobile")):
        return "terminal_mobile"
    # Windows, macOS, Linux desktops managed by Intune are workstations.
    return "poste_physique"


def _statut(management_state: str) -> str:
    s = (management_state or "").lower()
    if any(k in s for k in ("retire", "wipe", "delete", "discovered")):
        return "inactif"
    return "actif"


def _parse_dt(value: str) -> datetime | None:
    s = (value or "").strip()
    if not s or s.startswith("0001-01-01"):  # Graph's "never" sentinel
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _device_to_record(d: dict, strip_dom: bool) -> AssetRecord | None:
    did = str(d.get("id") or "")
    name = str(d.get("deviceName") or "") or did
    if not did and not name:
        return None
    if strip_dom:
        name = _strip_domain(name)

    os_name = str(d.get("operatingSystem") or "")
    os_version = str(d.get("osVersion") or "")
    device_type = str(d.get("deviceType") or "")
    owner_type = str(d.get("managedDeviceOwnerType") or "")
    compliance = str(d.get("complianceState") or "")
    model = str(d.get("model") or "").strip()
    manufacturer = str(d.get("manufacturer") or "").strip()
    serial = str(d.get("serialNumber") or "").strip()
    owner = str(d.get("userPrincipalName")
                or d.get("userDisplayName")
                or d.get("emailAddress") or "").strip()

    notes_bits = [f"intune-id={did}"]
    if device_type:
        notes_bits.append(f"device_type={device_type}")
    if model:
        notes_bits.append(f"model={model}")
    if serial:
        notes_bits.append(f"serial={serial}")
    if owner_type:
        notes_bits.append(f"owner_type={owner_type}")
    if compliance:
        notes_bits.append(f"compliance={compliance}")
    if d.get("azureADDeviceId"):
        notes_bits.append(f"aad_device_id={d['azureADDeviceId']}")
    if str(d.get("isEncrypted") or "").lower() == "true" or d.get("isEncrypted") is True:
        notes_bits.append("encrypted=true")

    return AssetRecord(
        external_key=f"intune-{did}".lower(),
        nom=name,
        type=_classify_device_type(os_name, device_type),
        description="Microsoft Intune — managed device",
        criticite=2,
        proprietaire=owner,
        fournisseur=manufacturer,
        os=os_name,
        version=os_version,
        statut=_statut(str(d.get("managementState") or "")),
        notes=" | ".join(notes_bits),
        last_login_at=_parse_dt(str(d.get("lastSyncDateTime") or "")),
        raw_data=d,
    )


def _fetch_managed_devices(token: str, *, strip_dom: bool, exclude_personal: bool,
                           only_compliant: bool, exclude_retired: bool,
                           errors: list[str]) -> list[AssetRecord]:
    out: list[AssetRecord] = []
    url: str | None = (f"{_GRAPH_BASE}/deviceManagement/managedDevices"
                       f"?$top={_PAGE_SIZE}")
    pages = 0
    while url and pages < _MAX_PAGES:
        pages += 1
        status, parsed, raw = _http("GET", url, token=token)
        if status != 200 or not isinstance(parsed, dict):
            errors.append(f"managed-devices: HTTP {status}")
            logger.warning("Intune GET managedDevices → HTTP %d (%s)",
                           status, raw[:200])
            break
        devices = parsed.get("value")
        if not isinstance(devices, list):
            break
        for d in devices:
            if not isinstance(d, dict):
                continue
            if exclude_personal and str(d.get("managedDeviceOwnerType") or "").lower() == "personal":
                continue
            if only_compliant and str(d.get("complianceState") or "").lower() != "compliant":
                continue
            if exclude_retired and _statut(str(d.get("managementState") or "")) == "inactif":
                continue
            rec = _device_to_record(d, strip_dom)
            if rec is not None:
                out.append(rec)
        url = parsed.get("@odata.nextLink") or None
    if pages >= _MAX_PAGES and url:
        errors.append(f"managed-devices: capped at {_MAX_PAGES} pages")
        logger.warning("Intune: managedDevices pagination capped at %d pages", _MAX_PAGES)
    logger.info("Intune: %d managed device(s) collected", len(out))
    return out


def _test(config: dict) -> dict:
    tenant_id = (config.get("tenant_id") or "").strip()
    client_id = (config.get("client_id") or "").strip()
    secret = (config.get("client_secret") or "")
    if not tenant_id or not client_id or not secret:
        return {"ok": False, "error": "Missing tenant_id, client_id or client_secret", "details": ""}
    try:
        token = _login(tenant_id, client_id, secret)
    except Exception as e:
        return {"ok": False, "error": f"auth: {e}", "details": ""}
    # Probe a single device page to confirm the app has the Graph permission.
    status, parsed, _raw = _http(
        "GET", f"{_GRAPH_BASE}/deviceManagement/managedDevices?$top=1", token=token)
    if status == 200 and isinstance(parsed, dict):
        return {"ok": True, "error": "",
                "details": "Auth + Graph managedDevices OK"}
    if status == 403:
        return {"ok": False,
                "error": "Auth OK but missing permission DeviceManagementManagedDevices.Read.All (admin consent?)",
                "details": ""}
    return {"ok": False, "error": f"Graph probe failed (HTTP {status})", "details": ""}


def _sync(config: dict, filters: dict) -> SyncResult:
    tenant_id = (config.get("tenant_id") or "").strip()
    client_id = (config.get("client_id") or "").strip()
    secret = (config.get("client_secret") or "")
    if not tenant_id or not client_id or not secret:
        return SyncResult(errors=["Missing tenant_id, client_id or client_secret"])

    strip_dom = bool(config.get("strip_domain", False))
    exclude_personal = bool(config.get("exclude_personal", False))
    only_compliant = bool(config.get("only_compliant", False))
    exclude_retired = bool(config.get("exclude_retired", False))

    errors: list[str] = []
    try:
        token = _login(tenant_id, client_id, secret)
    except Exception as e:
        logger.exception("Intune auth failed")
        return SyncResult(errors=[f"auth: {e}"])

    assets = _fetch_managed_devices(
        token, strip_dom=strip_dom, exclude_personal=exclude_personal,
        only_compliant=only_compliant, exclude_retired=exclude_retired,
        errors=errors)
    logger.info("Intune sync: %d assets total, %d error(s)", len(assets), len(errors))
    return SyncResult(assets=assets, errors=errors)


class IntuneAssetPlugin(AssetPlugin):
    plugin_type = "intune"
    label = "Microsoft Intune — appareils gérés"
    label_en = "Microsoft Intune — managed devices"
    config_schema = [
        {"key": "tenant_id", "label": "Tenant ID (Entra)",
         "label_en": "Tenant ID (Entra)", "type": "text", "required": True},
        {"key": "client_id", "label": "Client ID (app registration)",
         "label_en": "Client ID (app registration)", "type": "text", "required": True},
        {"key": "client_secret", "label": "Client secret",
         "label_en": "Client secret", "type": "password", "required": True},
        {"key": "exclude_personal", "label": "Exclure les appareils personnels (BYOD)",
         "label_en": "Exclude personal (BYOD) devices", "type": "checkbox", "required": False},
        {"key": "only_compliant", "label": "Seulement les appareils conformes",
         "label_en": "Compliant devices only", "type": "checkbox", "required": False},
        {"key": "exclude_retired", "label": "Ignorer les appareils en retrait/wipe",
         "label_en": "Skip retiring/wiping devices", "type": "checkbox", "required": False},
        {"key": "strip_domain", "label": "Ne garder que le hostname (sans domaine)",
         "label_en": "Keep hostname only (strip domain)", "type": "checkbox", "required": False},
    ]
    setup_guide = (
        "1. Portail Entra (entra.microsoft.com) → Applications → Inscriptions\n"
        "   d'applications → Nouvelle inscription.\n"
        "2. Noter l'ID de locataire (tenant_id) et l'ID d'application (client_id).\n"
        "3. Certificats & secrets → Nouveau secret client → copier la valeur\n"
        "   (client_secret ; non ré-affichée ensuite).\n"
        "4. API autorisées → Ajouter → Microsoft Graph → Autorisations\n"
        "   d'APPLICATION → DeviceManagementManagedDevices.Read.All,\n"
        "   puis 'Accorder un consentement administrateur'.\n"
        "5. Le connecteur mappe chaque appareil géré en actif (poste_physique,\n"
        "   ou terminal_mobile pour iOS/Android). Propriétaire = userPrincipalName,\n"
        "   fournisseur = manufacturer, OS/version depuis operatingSystem/osVersion,\n"
        "   dernière synchro Intune → dernière connexion. Modèle, n° de série,\n"
        "   conformité et type de propriété vont dans les notes.\n"
        "6. Intune n'expose pas d'IP côté managedDevices — le champ IP reste vide.\n"
        "7. Le jeton d'accès a ~1h de durée de vie ; le connecteur se\n"
        "   ré-authentifie à chaque sync. Pagination automatique."
    )
    setup_guide_en = (
        "1. Entra portal (entra.microsoft.com) → Applications → App\n"
        "   registrations → New registration.\n"
        "2. Record the Directory (tenant) ID and Application (client) ID.\n"
        "3. Certificates & secrets → New client secret → copy the value\n"
        "   (client_secret; shown only once).\n"
        "4. API permissions → Add → Microsoft Graph → APPLICATION\n"
        "   permissions → DeviceManagementManagedDevices.Read.All, then\n"
        "   'Grant admin consent'.\n"
        "5. The connector maps each managed device to an active asset\n"
        "   (poste_physique, or terminal_mobile for iOS/Android). Owner =\n"
        "   userPrincipalName, vendor = manufacturer, OS/version from\n"
        "   operatingSystem/osVersion, Intune last sync → last login. Model,\n"
        "   serial, compliance and ownership go into notes.\n"
        "6. Intune exposes no IP on managedDevices — the IP field stays empty.\n"
        "7. The access token lasts ~1h; the connector re-authenticates on\n"
        "   each sync. Automatic pagination."
    )

    async def test_connection(self, config: dict) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _test, config)

    async def sync(self, config: dict, filters: dict) -> SyncResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync, config, filters)
