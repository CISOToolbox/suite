from __future__ import annotations

import re
import urllib.parse
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, field_validator

from src.ssrf_guard import resolve_safe_target

_VALID_SCANNERS = {"trivy_fs", "trivy_image", "gitleaks", "semgrep"}
_BRANCH_RE = re.compile(r"^[a-zA-Z0-9._/\-]{1,200}$")
_REPO_SCHEMES = ("https://", "http://", "git@", "ssh://")
# An image reference must start with an alphanumeric (never '-', which would
# be parsed by `trivy image` as a flag → argument injection) and contain only
# registry/name/tag/digest characters.
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}$")


def _repo_host(url: str) -> str:
    """Host of a repo URL, in either the URL or the scp-like form."""
    if "://" in url:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    if "@" in url:  # git@host:owner/repo.git
        rest = url.split("@", 1)[1]
        return rest.split(":", 1)[0].split("/", 1)[0].lower()
    return ""


def _check_repo_url(v: str) -> str:
    """Validate a repo URL before it is handed to `git clone`.

    A regex over the URL *string* (the previous approach) is trivially
    bypassed — `http://2130706433/`, `http://127.1/`, `http://appsec-db:5432/`
    or any public name with an RFC1918 A record all slip through. So the
    host is extracted and actually resolved, reusing the same guard as the
    rest of the suite (fail-closed on an unresolvable name).
    """
    v = (v or "").strip()
    if not v:
        return v
    if v.startswith("-"):
        # `git clone … <url> <dir>`: a leading dash makes the URL an option.
        raise ValueError("Invalid repo URL")
    low = v.lower()
    if not any(low.startswith(p) for p in _REPO_SCHEMES):
        raise ValueError("Unsupported repo URL scheme")
    if "ext::" in low or "--upload-pack" in low:
        # git remote helpers / transport options run arbitrary commands.
        raise ValueError("Unsupported repo URL scheme")
    host = _repo_host(v)
    if not host:
        raise ValueError("Missing host in repo URL")
    try:
        resolve_safe_target(host)
    except ValueError as e:
        raise ValueError(f"Private/internal URLs are not allowed ({e})")
    return v


def _image_registry_host(ref: str) -> str:
    """Registry host of an image ref, or "" when it targets the default hub.

    Docker's own rule: the first path component is a registry only when it
    contains a "." or a ":", or is exactly "localhost". Anything else is a
    Docker Hub namespace ("library/nginx", "grafana/grafana").
    """
    if "/" not in ref:
        return ""
    head = ref.split("/", 1)[0]
    if head != "localhost" and "." not in head and ":" not in head:
        return ""
    return head.split(":", 1)[0] if ":" in head else head


def _clean_image_refs(v: list[str]) -> list[str]:
    clean = []
    for img in v:
        img = (img or "").strip()
        if not img:
            continue
        if not _IMAGE_REF_RE.fullmatch(img):
            raise ValueError(f"Invalid image reference: {img!r}")
        # The shape check above says nothing about where the ref points:
        # "169.254.169.254/x" or "10.0.0.5:5000/x" match it perfectly, and
        # `trivy image --image-src remote` would then fetch from there, with
        # the outcome observable through the surfaced error. Same treatment as
        # repo_url — resolve the registry and refuse internal targets.
        host = _image_registry_host(img)
        if host:
            try:
                resolve_safe_target(host)
            except ValueError as e:
                raise ValueError(f"Private/internal registry is not allowed ({e})")
        clean.append(img)
    return clean


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str
    picture: str
    role: str
    ai_enabled: str
    last_login: datetime | None
    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    role: str | None = None
    ai_enabled: str | None = None


# ── Applications ──────────────────────────────────────────────

def _validate_notification_emails(v: list[str] | None) -> list[str] | None:
    """FEAT-35 — normalize + validate the per-app recipient list."""
    if v is None:
        return None
    import re as _re
    out: list[str] = []
    for raw in v:
        e = (raw or "").strip().lower()
        if not e:
            continue
        if len(e) > 320 or not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
            raise ValueError(f"invalid email: {raw}")
        if e not in out:
            out.append(e)
    if len(out) > 20:
        raise ValueError("at most 20 notification recipients per application")
    return out


class ApplicationCreate(BaseModel):
    name: str
    description: str = ""
    repo_url: str = ""
    repo_branch: str = "main"
    repo_token: str = ""
    scan_paths: list[str] = []  # monorepo: subdirs to scan (empty = entire repo)
    docker_images: list[str] = []
    image_token: str = ""  # PAT for private container registries
    scan_frequency_hours: int = 24
    enabled_scanners: list[str] = ["trivy_fs", "gitleaks", "semgrep", "trivy_image"]
    criticality: str = "medium"
    notification_emails: list[str] = []
    notification_lang: str = "en"

    @field_validator("notification_emails")
    @classmethod
    def _v_notif_emails(cls, v):
        return _validate_notification_emails(v) or []

    @field_validator("notification_lang")
    @classmethod
    def _v_notif_lang(cls, v):
        if v not in ("fr", "en"):
            raise ValueError("notification_lang must be fr|en")
        return v

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be empty")
        return v.strip()

    @field_validator("repo_branch")
    @classmethod
    def safe_branch(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return "main"
        if not _BRANCH_RE.fullmatch(v) or v.startswith("-"):
            raise ValueError("Invalid branch name")
        return v

    @field_validator("repo_url")
    @classmethod
    def safe_repo_url(cls, v: str) -> str:
        return _check_repo_url(v)

    @field_validator("docker_images")
    @classmethod
    def safe_docker_images(cls, v: list[str]) -> list[str]:
        return _clean_image_refs(v)

    @field_validator("enabled_scanners")
    @classmethod
    def valid_scanners(cls, v: list[str]) -> list[str]:
        invalid = set(v) - _VALID_SCANNERS
        if invalid:
            raise ValueError(f"Unknown scanners: {invalid}")
        return list(dict.fromkeys(v))  # deduplicate, preserve order

    @field_validator("scan_paths")
    @classmethod
    def safe_scan_paths(cls, v: list[str]) -> list[str]:
        clean = []
        for p in v:
            p = p.strip().strip("/")
            if not p:
                continue
            if ".." in p or p.startswith("/") or "\x00" in p:
                raise ValueError(f"Invalid scan path (path traversal): {p}")
            clean.append(p)
        return clean


class ApplicationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repo_url: str | None = None
    repo_branch: str | None = None
    repo_token: str | None = None
    scan_paths: list[str] | None = None
    docker_images: list[str] | None = None
    image_token: str | None = None
    scan_frequency_hours: int | None = None
    enabled_scanners: list[str] | None = None
    enabled: bool | None = None
    criticality: str | None = None
    notification_emails: list[str] | None = None
    notification_lang: str | None = None

    @field_validator("notification_emails")
    @classmethod
    def _v_notif_emails(cls, v):
        return _validate_notification_emails(v)

    @field_validator("notification_lang")
    @classmethod
    def _v_notif_lang(cls, v):
        if v is not None and v not in ("fr", "en"):
            raise ValueError("notification_lang must be fr|en")
        return v

    @field_validator("repo_branch")
    @classmethod
    def safe_branch(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return "main"
        if not _BRANCH_RE.fullmatch(v) or v.startswith("-"):
            raise ValueError("Invalid branch name")
        return v

    @field_validator("repo_url")
    @classmethod
    def safe_repo_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _check_repo_url(v)

    @field_validator("docker_images")
    @classmethod
    def safe_docker_images(cls, v: list[str] | None) -> list[str] | None:
        return _clean_image_refs(v) if v is not None else v

    @field_validator("enabled_scanners")
    @classmethod
    def valid_scanners(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        invalid = set(v) - _VALID_SCANNERS
        if invalid:
            raise ValueError(f"Unknown scanners: {invalid}")
        return list(dict.fromkeys(v))

    @field_validator("scan_paths")
    @classmethod
    def safe_scan_paths(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        clean = []
        for p in v:
            p = p.strip().strip("/")
            if not p:
                continue
            if ".." in p or p.startswith("/") or "\x00" in p:
                raise ValueError(f"Invalid scan path (path traversal): {p}")
            clean.append(p)
        return clean


class ApplicationResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    repo_url: str
    repo_branch: str
    has_token: bool = False
    docker_images: list[str]
    scan_frequency_hours: int
    enabled_scanners: list[str]
    enabled: bool
    criticality: str
    owner_id: uuid.UUID | None
    last_scan_at: datetime | None
    created_at: datetime
    updated_at: datetime
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    notification_emails: list[str] = []
    notification_lang: str = "en"

    model_config = {"from_attributes": True}


# ── Findings ──────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str = ""
    scanner: str
    type: str
    severity: str
    title: str
    description: str
    target: str
    evidence: dict[str, Any]
    status: str
    dedup_key: str
    cve_id: str | None
    triaged_at: datetime | None
    triaged_by: str | None
    triage_notes: str
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingTriage(BaseModel):
    status: str
    triage_notes: str = ""
    # Fields consumed when status == "to_fix" — match BulkTriageRequest
    # so single-finding triage from the detail page produces a proper
    # measure (title / description / owner / due) instead of a stub.
    measure_title: str | None = None
    measure_description: str | None = None
    responsable: str | None = None
    echeance: str | None = None

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        allowed = {"new", "false_positive", "to_fix", "fixed"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}")
        return v


class FindingsStats(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    new: int = 0
    to_fix: int = 0
    false_positive: int = 0
    fixed: int = 0
    by_scanner: dict[str, int] = {}
    by_app: dict[str, int] = {}
    by_app_severity: dict[str, dict[str, int]] = {}  # {app: {critical: N, high: N, ...}}
    # Patch availability on active CVE findings (from Trivy fixed_version).
    cve_total: int = 0
    cve_with_patch: int = 0


# ── Scan Jobs ─────────────────────────────────────────────────

class ScanJobResponse(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str = ""
    scanner: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    findings_count: int
    diff: dict[str, Any]
    error: str
    triggered_by: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── SBOM ──────────────────────────────────────────────────────

class SBOMResponse(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    application_name: str = ""
    package_name: str
    version: str
    ecosystem: str
    license: str
    direct: bool
    parent_packages: list[str] = []
    depends_on: list[str] = []
    last_seen_at: datetime
    vulnerable: bool = False

    model_config = {"from_attributes": True}


# ── Measures ──────────────────────────────────────────────────

class MeasureUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    statut: Optional[str] = None
    responsable: Optional[str] = None
    echeance: Optional[str] = None
    progress_log: list[Any] | None = None


class MeasureResponse(BaseModel):
    id: str
    finding_id: uuid.UUID
    title: str
    description: str
    statut: str
    responsable: str
    echeance: str
    progress_log: list[Any]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── AI ────────────────────────────────────────────────────────

class AICompleteRequest(BaseModel):
    system: str
    user: str
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"


class AICompleteResponse(BaseModel):
    text: str


class AIConfigResponse(BaseModel):
    anthropic_configured: bool
    openai_configured: bool
    gemini_configured: bool = False
    providers: dict[str, dict[str, Any]]


class AIRuntimeResponse(BaseModel):
    managed: bool
    can_use: bool
    provider: str
    model: str
    anthropic_configured: bool
    openai_configured: bool
    gemini_configured: bool = False
    custom_configured: bool = False
