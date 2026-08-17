"""Cloud Temple (Shiva) asset connector.

Authenticates against the Shiva console API using a Personal Access
Token pair (client_id + secret), then pulls VMs and physical hosts
from the Compute modules (IaaS VMware vCenters + OpenIaaS / XOA), and
optionally physical colocation assets from the Housing module.

API reference:
  - https://cloud-temple.github.io/docs/en/console (auth + structure)
  - Terraform provider Cloud-Temple/terraform-provider-cloudtemple
    (internal/client/compute_*.go) for exact endpoint paths used here.

Endpoints hit during a sync:
  POST /api/iam/v2/auth/personal_access_token     (login — returns JWT)
  GET  /api/compute/v1/vcenters/virtual_machines  (VMware VMs)
  GET  /api/compute/v1/vcenters/virtual_machines/{id}  (VM detail — guest IP,
                                                   opt-in resolve_vmware_ips)
  GET  /api/compute/v1/vcenters/hosts             (ESX physical hosts)
  GET  /api/compute/v1/open_iaas/virtual_machines (Xen VMs, optional)
  GET  /api/compute/v1/open_iaas/hosts            (Xen hosts, optional)
  GET  /api/housing/v1/devices                    (physical colocation devices)
  GET  /api/housing/v1/racks                      (physical colocation racks)

The JWT has a 5-minute lifetime, we exchange once per sync and reuse
for all subsequent calls inside the same sync.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from src.plugins.base import (
    AssetPlugin, AssetRecord, SyncResult,
    strip_domain as _strip_domain,
    validate_public_http_url as _validate_base_url,
)

logger = logging.getLogger("asset-backend")

_REQ_TIMEOUT = 30
_DEFAULT_BASE = "https://shiva.cloud-temple.com"
_VMWARE_IP_MAX_LOOKUPS = 1000  # hard cap on per-VM detail calls per sync
# The Shiva API gateway (nginx) filters non-browser clients; send a
# browser-like UA like the official Terraform provider does.
_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects.

    `urlopen` follows 3xx automatically and re-sends the request headers —
    including `Authorization: Bearer <token>` — to the new location. A
    compromised or hostile Shiva endpoint could therefore bounce us to an
    internal host or to 169.254.169.254 *with the token attached*, right
    past the base-URL SSRF check. Returning None here makes urllib raise
    the 3xx as an HTTPError, which the caller reports as a status.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Module-level opener: same handler chain as `urlopen`, minus redirects.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _http_json(method: str, url: str, *, token: str = "",
               body: dict | None = None) -> tuple[int, Any, str]:
    """Minimal JSON-over-urllib helper. Returns (status, parsed_body, raw_text)."""
    data = None
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
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
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = None
    return status, parsed, raw


def _login(base: str, client_id: str, secret: str) -> str:
    url = base.rstrip("/") + "/api/iam/v2/auth/personal_access_token"
    status, _, raw = _http_json(
        "POST", url, body={"id": client_id, "secret": secret})
    if status != 200 and status != 201:
        raise RuntimeError(f"auth failed (HTTP {status})")
    token = (raw or "").strip().strip('"')
    if not token or "." not in token:
        raise RuntimeError("auth returned unexpected token payload")
    return token


def _classify_vm_type(os_name: str) -> str:
    low = (os_name or "").lower()
    if "server" in low or "linux" in low or "ubuntu" in low or "debian" in low \
            or "centos" in low or "rhel" in low or "red hat" in low:
        return "serveur_virtuel"
    return "poste_virtuel"


def _vm_power_to_statut(state: str) -> str:
    s = (state or "").lower()
    if s in ("on", "poweredon", "running"):
        return "actif"
    return "inactif"


def _host_statut(connected: bool, maintenance: bool) -> str:
    if maintenance or not connected:
        return "inactif"
    return "actif"


def _get(url: str, token: str) -> list[dict]:
    """GET that expects a JSON array. Returns [] on non-200."""
    status, parsed, raw = _http_json("GET", url, token=token)
    if status != 200:
        logger.warning("Cloud Temple GET %s → HTTP %d (%s)", url, status, raw[:200])
        return []
    if parsed is None:
        return []
    if isinstance(parsed, list):
        return parsed
    # Some endpoints wrap in {data: [...], ...}
    if isinstance(parsed, dict):
        for k in ("data", "items", "results"):
            v = parsed.get(k)
            if isinstance(v, list):
                return v
    return []


def _pick_vm_ip(detail: dict) -> str:
    """Extract the guest IP from a VMware VM *detail* object.

    Shiva reports the VMware Tools guest addresses under
    ``ipAddresses{primary, statics[]}`` — but ONLY on the detail endpoint
    (GET /virtual_machines/{id}); the list endpoint omits the field. We
    prefer `primary`, then the first routable IPv4 in `statics[].ipAddress`,
    then any routable IPv6. Loopback / link-local / unspecified are skipped.
    """
    addr = detail.get("ipAddresses") or {}
    if not isinstance(addr, dict):
        return ""
    v4 = v6 = ""

    def consider(val: Any) -> None:
        nonlocal v4, v6
        s = str(val or "").split("/")[0].strip()
        if not s:
            return
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return
        if ip.version == 4 and not v4:
            v4 = str(ip)
        elif ip.version == 6 and not v6:
            v6 = str(ip)

    consider(addr.get("primary"))
    statics = addr.get("statics")
    if isinstance(statics, list):
        for st in statics:
            if isinstance(st, dict):
                consider(st.get("ipAddress"))
    return v4 or v6


def _fetch_vmware_ip_map(base: str, token: str, vm_ids: list[str],
                         errors: list[str]) -> dict[str, str]:
    """VM-id → guest IP map for VMware VMs.

    The IP (VMware Tools) lives under ipAddresses.primary on the VM DETAIL
    endpoint only, so this makes one GET /virtual_machines/{id} per VM.
    Bounded by _VMWARE_IP_MAX_LOOKUPS. VMs with no reported IP (tools off,
    powered off) are simply absent from the map.
    """
    detail_base = base.rstrip("/") + "/api/compute/v1/vcenters/virtual_machines/"
    ip_map: dict[str, str] = {}
    seen: set[str] = set()
    calls = 0
    capped = False
    for vid in vm_ids:
        vid = str(vid or "")
        if not vid or vid in seen:
            continue
        seen.add(vid)
        if calls >= _VMWARE_IP_MAX_LOOKUPS:
            capped = True
            break
        calls += 1
        url = detail_base + urllib.parse.quote(vid, safe="")
        try:
            status, parsed, _raw = _http_json("GET", url, token=token)
        except Exception:
            continue
        if status != 200 or not isinstance(parsed, dict):
            continue
        ip = _pick_vm_ip(parsed)
        if ip:
            ip_map[vid] = ip
    if capped:
        errors.append(f"vmware-ips: capped at {_VMWARE_IP_MAX_LOOKUPS} VMs")
        logger.warning("Cloud Temple: VMware IP resolution capped at %d VM(s)",
                       _VMWARE_IP_MAX_LOOKUPS)
    logger.info("Cloud Temple: resolved %d VMware IP(s) from %d detail call(s)",
                len(ip_map), calls)
    return ip_map


def _fetch_vmware_vms(base: str, token: str, strip_dom: bool,
                      exclude_templates: bool, resolve_ips: bool,
                      errors: list[str]) -> list[AssetRecord]:
    url = base.rstrip("/") + "/api/compute/v1/vcenters/virtual_machines"
    out: list[AssetRecord] = []
    try:
        entries = _get(url, token)
    except Exception as e:
        errors.append(f"vmware-vms: {type(e).__name__}")
        return out
    for v in entries:
        if not isinstance(v, dict):
            continue
        if exclude_templates and v.get("template"):
            continue
        vid = str(v.get("id") or v.get("moref") or "")
        name = str(v.get("name") or "") or vid
        if not vid and not name:
            continue
        if strip_dom:
            name = _strip_domain(name)
        os_obj = v.get("operatingSystem") or {}
        os_name = str(os_obj.get("name") or "") if isinstance(os_obj, dict) else ""
        mm = v.get("machineManager") or {}
        mm_name = str(mm.get("name") or "") if isinstance(mm, dict) else ""
        cpu = v.get("cpu") or 0
        mem = v.get("memory") or 0
        notes_bits = [f"ctvm-vmware={vid}"]
        if cpu or mem:
            notes_bits.append(f"cpu={cpu}")
            notes_bits.append(f"ram_bytes={mem}")
        if mm_name:
            notes_bits.append(f"vcenter={mm_name}")
        out.append(AssetRecord(
            external_key=f"ct-vm-vmware-{vid}".lower(),
            nom=name,
            type=_classify_vm_type(os_name),
            description="Cloud Temple — IaaS VMware VM",
            criticite=3,
            fournisseur="Cloud Temple",
            os=os_name,
            statut=_vm_power_to_statut(str(v.get("powerState") or "")),
            notes=" | ".join(notes_bits),
            raw_data=v,
        ))
    if resolve_ips and out:
        vids = [str(r.raw_data.get("id") or "") for r in out]
        ip_map = _fetch_vmware_ip_map(base, token, vids, errors)
        if ip_map:
            for r in out:
                ip = ip_map.get(str(r.raw_data.get("id") or ""))
                if ip:
                    r.ip_address = ip
    logger.info("Cloud Temple: %d VMware VM(s) collected", len(out))
    return out


def _fetch_vmware_hosts(base: str, token: str, strip_dom: bool,
                        errors: list[str]) -> list[AssetRecord]:
    url = base.rstrip("/") + "/api/compute/v1/vcenters/hosts"
    out: list[AssetRecord] = []
    try:
        entries = _get(url, token)
    except Exception as e:
        errors.append(f"vmware-hosts: {type(e).__name__}")
        return out
    for h in entries:
        if not isinstance(h, dict):
            continue
        hid = str(h.get("id") or h.get("moref") or "")
        name = str(h.get("name") or "") or hid
        if not hid and not name:
            continue
        if strip_dom:
            name = _strip_domain(name)
        metrics = h.get("metrics") or {}
        esx = metrics.get("esx") or {} if isinstance(metrics, dict) else {}
        cpu = metrics.get("cpu") or {} if isinstance(metrics, dict) else {}
        mem = metrics.get("memory") or {} if isinstance(metrics, dict) else {}
        os_name = str(esx.get("fullName") or "") if isinstance(esx, dict) else ""
        version = str(esx.get("version") or "") if isinstance(esx, dict) else ""
        connected = bool(metrics.get("connected", True)) if isinstance(metrics, dict) else True
        maintenance = bool(metrics.get("maintenanceMode", False)) if isinstance(metrics, dict) else False
        mm = h.get("machineManager") or {}
        mm_name = str(mm.get("name") or "") if isinstance(mm, dict) else ""
        notes_bits = [f"ct-host-vmware={hid}"]
        if isinstance(cpu, dict) and cpu.get("cpuCores"):
            notes_bits.append(f"cpu_cores={cpu['cpuCores']}")
        if isinstance(mem, dict) and mem.get("memorySize"):
            notes_bits.append(f"ram_bytes={mem['memorySize']}")
        if mm_name:
            notes_bits.append(f"vcenter={mm_name}")
        out.append(AssetRecord(
            external_key=f"ct-host-vmware-{hid}".lower(),
            nom=name,
            type="serveur_physique",
            description="Cloud Temple — ESXi host",
            criticite=4,
            fournisseur="Cloud Temple",
            os=os_name,
            version=version,
            statut=_host_statut(connected, maintenance),
            notes=" | ".join(notes_bits),
            raw_data=h,
        ))
    logger.info("Cloud Temple: %d VMware host(s) collected", len(out))
    return out


def _fetch_openiaas_vms(base: str, token: str, strip_dom: bool,
                        errors: list[str]) -> list[AssetRecord]:
    url = base.rstrip("/") + "/api/compute/v1/open_iaas/virtual_machines"
    out: list[AssetRecord] = []
    try:
        entries = _get(url, token)
    except Exception as e:
        errors.append(f"openiaas-vms: {type(e).__name__}")
        return out
    for v in entries:
        if not isinstance(v, dict):
            continue
        vid = str(v.get("id") or v.get("internalId") or "")
        name = str(v.get("name") or "") or vid
        if not vid and not name:
            continue
        if strip_dom:
            name = _strip_domain(name)
        os_name = str(v.get("operatingSystemName") or "")
        cpu = v.get("cpu") or 0
        mem = v.get("memory") or 0
        host = v.get("host") or {}
        host_name = str(host.get("name") or "") if isinstance(host, dict) else ""
        mm = v.get("machineManager") or {}
        mm_name = str(mm.get("name") or "") if isinstance(mm, dict) else ""
        addr = v.get("addresses") or {}
        ipv4 = str(addr.get("ipv4") or "").strip() if isinstance(addr, dict) else ""
        notes_bits = [f"ct-vm-xen={vid}"]
        if cpu or mem:
            notes_bits.append(f"cpu={cpu}")
            notes_bits.append(f"ram_bytes={mem}")
        if host_name:
            notes_bits.append(f"xen_host={host_name}")
        if mm_name:
            notes_bits.append(f"xoa={mm_name}")
        out.append(AssetRecord(
            external_key=f"ct-vm-xen-{vid}".lower(),
            nom=name,
            type=_classify_vm_type(os_name),
            description="Cloud Temple — OpenIaaS (XOA/Xen) VM",
            criticite=3,
            fournisseur="Cloud Temple",
            os=os_name,
            statut=_vm_power_to_statut(str(v.get("powerState") or "")),
            notes=" | ".join(notes_bits),
            ip_address=ipv4,
            raw_data=v,
        ))
    logger.info("Cloud Temple: %d OpenIaaS VM(s) collected", len(out))
    return out


def _fetch_openiaas_hosts(base: str, token: str, strip_dom: bool,
                          errors: list[str]) -> list[AssetRecord]:
    url = base.rstrip("/") + "/api/compute/v1/open_iaas/hosts"
    out: list[AssetRecord] = []
    try:
        entries = _get(url, token)
    except Exception as e:
        errors.append(f"openiaas-hosts: {type(e).__name__}")
        return out
    for h in entries:
        if not isinstance(h, dict):
            continue
        hid = str(h.get("id") or h.get("internalId") or "")
        name = str(h.get("name") or "") or hid
        if not hid and not name:
            continue
        if strip_dom:
            name = _strip_domain(name)
        metrics = h.get("metrics") or {}
        xoa = metrics.get("xoa") or {} if isinstance(metrics, dict) else {}
        mem = metrics.get("memory") or {} if isinstance(metrics, dict) else {}
        cpu = metrics.get("cpu") or {} if isinstance(metrics, dict) else {}
        os_name = str(xoa.get("fullName") or "XCP-ng / XenServer") if isinstance(xoa, dict) else "XCP-ng / XenServer"
        version = str(xoa.get("version") or "") if isinstance(xoa, dict) else ""
        power = str(h.get("powerState") or "").lower()
        maintenance = False
        ud = h.get("updateData") or {}
        if isinstance(ud, dict):
            maintenance = bool(ud.get("maintenanceMode", False))
        connected = power in ("running", "on", "active", "")
        notes_bits = [f"ct-host-xen={hid}"]
        if isinstance(cpu, dict) and cpu.get("cores"):
            notes_bits.append(f"cpu_cores={cpu['cores']}")
        if isinstance(mem, dict) and mem.get("size"):
            notes_bits.append(f"ram_bytes={mem['size']}")
        out.append(AssetRecord(
            external_key=f"ct-host-xen-{hid}".lower(),
            nom=name,
            type="serveur_physique",
            description="Cloud Temple — XCP-ng host",
            criticite=4,
            fournisseur="Cloud Temple",
            os=os_name,
            version=version,
            statut=_host_statut(connected, maintenance),
            notes=" | ".join(notes_bits),
            raw_data=h,
        ))
    logger.info("Cloud Temple: %d OpenIaaS host(s) collected", len(out))
    return out


# Housing (physical colocation) — schema:
#   GET /api/housing/v1/devices  {items: [...], total, page, size, pages}
#   GET /api/housing/v1/racks    same envelope
# The API is a NetBox-compatible surface (Cloud Temple runs NetBox for
# DCIM). Fields we rely on:
#   device.id, device.name, device.device_type{manufacturer{name}, model},
#   device.platform{name}, device.site{name}, device.location{name},
#   device.rack{name}, device.position, device.status{value},
#   device.primary_ip4{address}, device.serial, device.asset_tag,
#   device.tenant{name}, device.description.
#   rack.id, rack.name, rack.site{name}, rack.u_height, rack.status{value},
#   rack.device_count.
_HOUSING_PAGE_SIZE = 100
_HOUSING_MAX_PAGES = 50  # hard cap to avoid runaway loops (~5k items)


def _ct_name(obj: Any, *keys: str) -> str:
    """Extract a human-readable name from a nested {id, name, ...} dict.
    Accepts multiple candidate keys and walks into dicts transparently."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for k in keys or ("name", "label", "display", "slug"):
            v = obj.get(k)
            if isinstance(v, str) and v:
                return v
            if isinstance(v, (int, float)):
                return str(v)
    return ""


def _ct_status_to_statut(status_obj: Any) -> str:
    """Map a Housing status object to the Asset statut enum.
    Accepts either {'value': 'active'} or a raw string."""
    raw = ""
    if isinstance(status_obj, dict):
        raw = str(status_obj.get("value") or status_obj.get("label") or "").lower()
    elif isinstance(status_obj, str):
        raw = status_obj.lower()
    if raw in ("active", "online", "running", "staged"):
        return "actif"
    if raw in ("planned", "inventory"):
        return "en_cours"
    if raw in ("offline", "failed", "decommissioning"):
        return "inactif"
    if raw in ("retired",):
        return "retire"
    return "actif"  # default: assume deployed unless told otherwise


def _strip_cidr(addr: str) -> str:
    """primary_ip4.address is typically 'a.b.c.d/24' — strip the /prefix."""
    if not addr:
        return ""
    return addr.split("/", 1)[0].strip()


def _paginate(base: str, path: str, token: str) -> list[dict]:
    """Walk all pages of a Housing endpoint. Honours the standard
    {items, total, page, size, pages} envelope. Caps at _HOUSING_MAX_PAGES."""
    collected: list[dict] = []
    for page in range(1, _HOUSING_MAX_PAGES + 1):
        qs = f"?page={page}&size={_HOUSING_PAGE_SIZE}"
        url = base.rstrip("/") + path + qs
        status, parsed, _raw = _http_json("GET", url, token=token)
        if status != 200 or not isinstance(parsed, (list, dict)):
            if status != 200:
                logger.warning("Cloud Temple housing %s (page %d) → HTTP %d",
                               path, page, status)
            break
        items: list[dict] = []
        total_pages = 1
        if isinstance(parsed, list):
            items = [x for x in parsed if isinstance(x, dict)]
            collected.extend(items)
            # Bare list (no envelope): stop when the page is not full.
            if len(items) < _HOUSING_PAGE_SIZE:
                break
            continue
        elif isinstance(parsed, dict):
            items = [x for x in (parsed.get("items") or []) if isinstance(x, dict)]
            total_pages = int(parsed.get("pages") or 1)
        collected.extend(items)
        if page >= total_pages:
            break
    return collected


def _fetch_housing(base: str, token: str, strip_dom: bool,
                   errors: list[str]) -> list[AssetRecord]:
    """Pull Housing devices + racks via the documented endpoints.
    See the Shiva Housing OpenAPI spec at
    https://shiva.cloud-temple.com/api/housing/docs/swagger.yml"""
    out: list[AssetRecord] = []

    # ── Devices (the bulk of what goes into Asset) ──
    try:
        devices = _paginate(base, "/api/housing/v1/devices", token)
    except Exception as e:
        errors.append(f"housing-devices: {type(e).__name__}")
        devices = []
    for d in devices:
        did = str(d.get("id") or "")
        name = str(d.get("name") or d.get("display") or did)
        if not (did or name):
            continue
        if strip_dom:
            name = _strip_domain(name)

        dt = d.get("device_type") or {}
        manufacturer = _ct_name(dt.get("manufacturer") if isinstance(dt, dict) else None)
        model = _ct_name(dt, "model", "slug")
        fournisseur = manufacturer or "Cloud Temple"

        platform = _ct_name(d.get("platform"))
        site = _ct_name(d.get("site"))
        location = _ct_name(d.get("location"))
        rack = _ct_name(d.get("rack"))
        position = str(d.get("position") or "").strip()
        face = str(d.get("face") or "").strip()
        role = _ct_name(d.get("device_role"))
        tenant_name = _ct_name(d.get("tenant"))
        serial = str(d.get("serial") or "").strip()
        asset_tag = str(d.get("asset_tag") or "").strip()
        description = (d.get("description") or "").strip()

        # Build a readable localisation: "Site / Location / Rack-name U3 (front)".
        loc_parts = []
        if site: loc_parts.append(site)
        if location and location != site: loc_parts.append(location)
        if rack:
            rack_loc = "rack " + rack
            if position:
                rack_loc += f" U{position}"
            if face:
                rack_loc += f" ({face})"
            loc_parts.append(rack_loc)
        localisation = " / ".join(loc_parts)

        # IP address from primary_ip4 (strip /CIDR suffix)
        ip = ""
        for key in ("primary_ip4", "primary_ip"):
            v = d.get(key)
            if isinstance(v, dict) and v.get("address"):
                ip = _strip_cidr(str(v["address"]))
                break

        notes_bits = [f"ct-housing-device={did}"]
        if role: notes_bits.append(f"role={role}")
        if model: notes_bits.append(f"model={model}")
        if serial: notes_bits.append(f"serial={serial}")
        if asset_tag: notes_bits.append(f"tag={asset_tag}")
        if tenant_name: notes_bits.append(f"tenant={tenant_name}")

        out.append(AssetRecord(
            external_key=f"ct-housing-device-{did}".lower(),
            nom=name,
            type="serveur_physique",
            description=(description or f"Cloud Temple Housing — {manufacturer} {model}".strip()),
            criticite=4,
            fournisseur=fournisseur,
            os=platform,
            localisation=localisation,
            ip_address=ip,
            statut=_ct_status_to_statut(d.get("status")),
            notes=" | ".join(notes_bits),
            raw_data=d,
        ))
    logger.info("Cloud Temple Housing: %d device(s) collected", len(out))

    # ── Racks (optional — they carry devices, useful as dependencies) ──
    try:
        racks = _paginate(base, "/api/housing/v1/racks", token)
    except Exception as e:
        errors.append(f"housing-racks: {type(e).__name__}")
        racks = []
    rack_count_before = len(out)
    for r in racks:
        rid = str(r.get("id") or "")
        name = str(r.get("name") or r.get("display") or rid)
        if not (rid or name):
            continue
        site = _ct_name(r.get("site"))
        location = _ct_name(r.get("location"))
        loc_parts = [p for p in (site, location) if p and p not in ("", site)]
        localisation = " / ".join([site] + ([location] if location and location != site else []))
        u_height = r.get("u_height")
        device_count = r.get("device_count")

        notes_bits = [f"ct-housing-rack={rid}"]
        if u_height: notes_bits.append(f"u_height={u_height}")
        if device_count: notes_bits.append(f"devices={device_count}")
        rtype = _ct_name(r.get("type"), "value", "label")
        if rtype: notes_bits.append(f"rack_type={rtype}")

        out.append(AssetRecord(
            external_key=f"ct-housing-rack-{rid}".lower(),
            nom=f"Rack {name}" if name.lower() != "rack" else name,
            # No "rack" in our enum — serveur_physique is the closest
            # (it IS hosted physical infrastructure). Notes flag it.
            type="serveur_physique",
            description="Cloud Temple Housing — Rack",
            criticite=4,
            fournisseur="Cloud Temple",
            localisation=localisation,
            statut=_ct_status_to_statut(r.get("status")),
            notes=" | ".join(notes_bits),
            raw_data=r,
        ))
    logger.info("Cloud Temple Housing: %d rack(s) collected",
                len(out) - rack_count_before)

    if not out:
        errors.append("Housing: no devices or racks returned")
    return out


def _test(config: dict) -> dict:
    base = (config.get("api_base_url") or _DEFAULT_BASE).strip()
    err = _validate_base_url(base)
    if err:
        return {"ok": False, "error": err, "details": ""}
    client_id = (config.get("client_id") or "").strip()
    secret = (config.get("client_secret") or "")
    if not client_id or not secret:
        return {"ok": False, "error": "Missing client_id or client_secret", "details": ""}
    try:
        token = _login(base, client_id, secret)
    except Exception as e:
        return {"ok": False, "error": f"auth: {type(e).__name__}", "details": ""}
    parts = token.split(".")
    msg = f"Auth OK ({len(parts)}-part JWT, {len(token)} chars)"
    return {"ok": True, "error": "", "details": msg}


def _sync(config: dict, filters: dict) -> SyncResult:
    base = (config.get("api_base_url") or _DEFAULT_BASE).strip()
    err = _validate_base_url(base)
    if err:
        return SyncResult(errors=[f"Invalid base URL: {err}"])
    client_id = (config.get("client_id") or "").strip()
    secret = (config.get("client_secret") or "")
    if not client_id or not secret:
        return SyncResult(errors=["Missing client_id or client_secret"])

    include_vmware = bool(config.get("include_vmware", True))
    include_openiaas = bool(config.get("include_openiaas", False))
    include_physical = bool(config.get("include_physical_hosts", True))
    include_housing = bool(config.get("include_housing", False))
    exclude_templates = bool(config.get("exclude_templates", True))
    resolve_ips = bool(config.get("resolve_vmware_ips", True))
    strip_dom = bool(config.get("strip_domain", False))

    errors: list[str] = []
    try:
        token = _login(base, client_id, secret)
    except Exception as e:
        logger.exception("Cloud Temple auth failed")
        return SyncResult(errors=[f"auth: {type(e).__name__}"])

    assets: list[AssetRecord] = []
    if include_vmware:
        assets.extend(_fetch_vmware_vms(base, token, strip_dom, exclude_templates,
                                        resolve_ips, errors))
        if include_physical:
            assets.extend(_fetch_vmware_hosts(base, token, strip_dom, errors))
    if include_openiaas:
        assets.extend(_fetch_openiaas_vms(base, token, strip_dom, errors))
        if include_physical:
            assets.extend(_fetch_openiaas_hosts(base, token, strip_dom, errors))
    if include_housing:
        assets.extend(_fetch_housing(base, token, strip_dom, errors))

    logger.info("Cloud Temple sync: %d assets total, %d error(s)", len(assets), len(errors))
    return SyncResult(assets=assets, errors=errors)


class CloudTempleAssetPlugin(AssetPlugin):
    plugin_type = "cloudtemple"
    label = "Cloud Temple (Shiva) — VMs + hôtes physiques"
    label_en = "Cloud Temple (Shiva) — VMs + physical hosts"
    config_schema = [
        {"key": "api_base_url", "label": "URL de l'API",
         "label_en": "API base URL", "type": "text", "required": False,
         "placeholder": _DEFAULT_BASE},
        {"key": "client_id", "label": "Client ID (PAT)",
         "label_en": "Client ID (PAT)", "type": "text", "required": True},
        {"key": "client_secret", "label": "Secret ID (PAT)",
         "label_en": "Secret ID (PAT)", "type": "password", "required": True},
        {"key": "include_vmware", "label": "Inclure IaaS VMware (vCenter)",
         "label_en": "Include IaaS VMware (vCenter)", "type": "checkbox", "required": False},
        {"key": "include_openiaas", "label": "Inclure OpenIaaS (XCP-ng / XOA)",
         "label_en": "Include OpenIaaS (XCP-ng / XOA)", "type": "checkbox", "required": False},
        {"key": "include_physical_hosts", "label": "Inclure les hôtes physiques (ESXi, XCP-ng)",
         "label_en": "Include physical hosts (ESXi, XCP-ng)", "type": "checkbox", "required": False},
        {"key": "include_housing", "label": "Inclure Housing (colocation physique)",
         "label_en": "Include Housing (physical colocation)", "type": "checkbox", "required": False},
        {"key": "resolve_vmware_ips", "label": "Récupérer les IP des VMs VMware (1 appel détail par VM)",
         "label_en": "Fetch VMware VM IPs (one detail call per VM)", "type": "checkbox",
         "required": False, "default": True},
        {"key": "exclude_templates", "label": "Ignorer les templates de VM",
         "label_en": "Skip VM templates", "type": "checkbox", "required": False},
        {"key": "strip_domain", "label": "Ne garder que le hostname (sans domaine)",
         "label_en": "Keep hostname only (strip domain)", "type": "checkbox", "required": False},
    ]
    setup_guide = (
        "1. Depuis la console Cloud Temple (https://shiva.cloud-temple.com), \n"
        "   profil → 'Jeton d'accès personnel' → 'Nouveau access token personnel'.\n"
        "2. Noter le Client ID + Secret ID (le secret n'est plus affiché après).\n"
        "3. Permissions minimales recommandées :\n"
        "   - compute_iaas_vmware_read (pour VMs + ESXi)\n"
        "   - compute_iaas_opensource_read (si tu utilises XCP-ng)\n"
        "   - housing_read (si tu actives l'option Housing)\n"
        "4. Le token JWT obtenu après échange a une durée de vie de 5 min ;\n"
        "   le connecteur se ré-authentifie à chaque sync.\n"
        "5. Le connecteur marque statut=inactif quand powerState≠on\n"
        "   ou quand un hôte est en maintenance/déconnecté.\n"
        "6. Les VMs templates sont ignorées par défaut (option configurable).\n"
        "7. Housing : liste les devices et racks physiques en colocation.\n"
        "   Les devices sont mappés en serveur_physique avec site, rack,\n"
        "   position U, IP primaire, serial/asset_tag, fabricant et modèle.\n"
        "   Les racks sont également inventoriés (avec nb de U, nb de\n"
        "   devices). Pagination automatique (100 par page, max 5000).\n"
        "8. IP des VMs VMware : l'IP invité (VMware Tools) n'est exposée\n"
        "   que sur le détail d'une VM (champ ipAddresses.primary), pas\n"
        "   dans la liste. Active 'Récupérer les IP des VMs VMware' pour\n"
        "   faire un appel détail par VM et remonter l'IP — nécessite que\n"
        "   les VMware Tools tournent (VM allumée). Coût : un appel API\n"
        "   supplémentaire par VM (borné à 1000/sync)."
    )
    setup_guide_en = (
        "1. From the Cloud Temple console (https://shiva.cloud-temple.com),\n"
        "   profile → 'Personal access token' → 'New personal access token'.\n"
        "2. Record the Client ID + Secret ID (secret shown only once).\n"
        "3. Minimum recommended roles:\n"
        "   - compute_iaas_vmware_read (for VMs + ESXi)\n"
        "   - compute_iaas_opensource_read (if you use XCP-ng)\n"
        "   - housing_read (if you enable the Housing option)\n"
        "4. The issued JWT is valid for 5 minutes — the connector\n"
        "   re-authenticates on each sync.\n"
        "5. Assets are marked statut=inactif when powerState≠on, or when\n"
        "   a host is in maintenance mode / disconnected.\n"
        "6. VM templates are skipped by default (configurable).\n"
        "7. Housing: lists physical colocation devices and racks.\n"
        "   Devices map to serveur_physique with site, rack, U position,\n"
        "   primary IP, serial/asset_tag, manufacturer and model.\n"
        "   Racks are also inventoried (with U height and device count).\n"
        "   Auto-paginated (100 per page, up to 5000 items).\n"
        "8. VMware VM IPs: the guest IP (VMware Tools) is exposed only on a\n"
        "   VM's detail (ipAddresses.primary), not in the list. Enable\n"
        "   'Fetch VMware VM IPs' to make one detail call per VM and pull\n"
        "   the IP — requires VMware Tools running (VM powered on). Cost:\n"
        "   one extra API call per VM (capped at 1000/sync)."
    )

    async def test_connection(self, config: dict) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _test, config)

    async def sync(self, config: dict, filters: dict) -> SyncResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync, config, filters)
