"""Scanner engine: clone repo, run tools, parse output, return normalized findings."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid

from src.crypto import decrypt_token

logger = logging.getLogger("appsec-scanners")

SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "900"))


def _safe_scan_target(base_dir: str, sub_path: str) -> str | None:
    """Resolve sub_path under base_dir and verify it doesn't escape.
    Returns the resolved path or None if invalid (path traversal)."""
    target = os.path.realpath(os.path.join(base_dir, sub_path.strip("/")))
    base = os.path.realpath(base_dir)
    if not target.startswith(base + os.sep) and target != base:
        logger.warning("Path traversal blocked: %s escapes %s", sub_path, base_dir)
        return None
    if not os.path.isdir(target):
        logger.warning("scan_path %s does not exist in cloned repo", sub_path)
        return None
    return target


def _inject_token(repo_url: str, token: str) -> str:
    """Rebuild the URL with x-access-token credentials.

    Strips any existing userinfo (e.g. Azure DevOps URLs already contain
    an `{org}@` prefix that would otherwise produce a double-`@` URL
    rejected by curl with "Bad hostname").
    """
    if not token or "://" not in repo_url:
        return repo_url
    proto, rest = repo_url.split("://", 1)
    # Strip existing userinfo: everything before the first '@' in the
    # authority component (before the first '/').
    authority_end = rest.find("/")
    authority = rest if authority_end < 0 else rest[:authority_end]
    path = "" if authority_end < 0 else rest[authority_end:]
    if "@" in authority:
        authority = authority.split("@", 1)[1]
    return f"{proto}://x-access-token:{token}@{authority}{path}"


def _revalidate_repo_host(repo_url: str) -> None:
    """Re-resolve the repo host immediately before handing it to git.

    _check_repo_url (schemas.py) vets the host when the request is parsed, but
    the clone happens later in a background scan — a name that resolved to a
    public address then can point at 169.254.169.254 by the time git runs, and
    the clone URL carries the access token. git re-resolves on its own and
    rewriting the URL to an IP would break TLS certificate validation, so the
    window cannot be closed entirely; re-checking here shrinks it from the
    whole scan queue delay to the microseconds before exec.
    """
    from urllib.parse import urlparse

    from src.ssrf_guard import resolve_safe_target

    url = (repo_url or "").strip()
    if "://" in url:
        host = (urlparse(url).hostname or "").lower()
    elif "@" in url:  # git@host:owner/repo.git
        host = url.split("@", 1)[1].split(":", 1)[0].split("/", 1)[0].lower()
    else:
        host = ""
    if not host:
        raise RuntimeError("Missing host in repo URL")
    try:
        resolve_safe_target(host)
    except ValueError as e:
        raise RuntimeError(f"Repo host is not allowed ({e})")


def get_remote_head(repo_url: str, branch: str, token_encrypted: str) -> str:
    _revalidate_repo_host(repo_url)
    token = decrypt_token(token_encrypted)
    url = _inject_token(repo_url, token)
    cmd = ["git", "ls-remote", url, f"refs/heads/{branch}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split()[0]
    except Exception as e:
        # Never log the URL with the token — use the original repo_url.
        logger.warning("git ls-remote failed for %s: %s", repo_url, type(e).__name__)
    return ""


def _sanitize_git_error(stderr: str, repo_url: str) -> str:
    """Strip credentials from git error messages. git stderr often
    includes the full URL (with the injected x-access-token) — leaking
    the PAT to the UI. We replace the token with '****'."""
    import re
    sanitized = re.sub(r"x-access-token:[^@]+@", "x-access-token:****@", stderr)
    # Also strip any raw token fragments that git might echo differently
    sanitized = re.sub(r"'https?://x-access-token:[^']*'", "'<redacted-url>'", sanitized)
    return sanitized[:300]


def _clone_repo(repo_url: str, branch: str, token_encrypted: str) -> str:
    _revalidate_repo_host(repo_url)
    token = decrypt_token(token_encrypted)
    if token_encrypted and not token:
        logger.warning("Token decryption returned empty for repo %s — "
                       "ENCRYPTION_KEY may have changed since the token was stored",
                       repo_url)
    clone_url = _inject_token(repo_url, token)

    tmp_dir = tempfile.mkdtemp(prefix="appsec-")
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--branch", branch, clone_url, tmp_dir]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if result.returncode != 0:
            stderr = _sanitize_git_error((result.stderr or "").strip(), repo_url)
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed (exit {result.returncode}): {stderr}")
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError("Git clone timed out after 120s")
    except RuntimeError:
        raise
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Git clone failed: {e}")
    return tmp_dir


def _cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def _safe_rel_path(rel_path: str) -> str | None:
    """Validate an untrusted repo-relative path (from finding evidence).
    Rejects absolute paths, parent traversal, NUL and empty. Returns the
    normalized POSIX-style relative path or None if unsafe."""
    if not rel_path or "\x00" in rel_path:
        return None
    p = rel_path.strip().lstrip("/")
    if not p or os.path.isabs(p):
        return None
    parts = [seg for seg in p.replace("\\", "/").split("/") if seg not in ("", ".")]
    if any(seg == ".." for seg in parts):
        return None
    return "/".join(parts) if parts else None


def fetch_file_window(repo_url: str, branch: str, commit: str, token_encrypted: str,
                      rel_path: str, line: int, radius: int = 40,
                      max_chars: int = 6000) -> dict:
    """Fetch ONE file at the scanned commit and return a code window around
    `line` (1-indexed) for AI deep analysis. Best-effort: never raises — on
    any failure returns {"ok": False, "note": <reason>}. Uses a shallow,
    sparse, single-file checkout pinned to `commit` when possible (falls back
    to the branch tip, flagged in the note)."""
    safe = _safe_rel_path(rel_path)
    if not safe:
        return {"ok": False, "note": "path"}
    token = decrypt_token(token_encrypted)
    if token_encrypted and not token:
        return {"ok": False, "note": "token"}
    url = _inject_token(repo_url, token)
    if "://" not in url:
        return {"ok": False, "note": "no_repo"}

    tmp_dir = tempfile.mkdtemp(prefix="appsec-file-")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

    def _git(args: list[str]) -> int:
        try:
            r = subprocess.run(["git", "-C", tmp_dir, *args], capture_output=True,
                               text=True, timeout=60, env=env)
            return r.returncode
        except Exception:
            return 1

    def _fetch(ref: str) -> bool:
        # `branch` reaches here from the request, and `git fetch … origin <ref>`
        # parses a leading dash as an option, not a refspec. git validates OIDs
        # so nothing was proven exploitable, but the shape of the bug is the
        # same one that made `_check_repo_url` reject a leading dash.
        if not ref or ref.startswith("-"):
            return False
        # Try a partial (blob-less) shallow fetch first; retry without the
        # filter for servers that don't support partial clone.
        for extra in (["--filter=blob:none"], []):
            if _git(["fetch", "--depth", "1", *extra, "origin", ref]) == 0:
                return _git(["checkout", "-q", "FETCH_HEAD"]) == 0
        return False

    try:
        if (_git(["init", "-q"]) != 0
                or _git(["remote", "add", "origin", url]) != 0
                or _git(["sparse-checkout", "init", "--no-cone"]) != 0
                or _git(["sparse-checkout", "set", safe]) != 0):
            return {"ok": False, "note": "setup"}

        note = ""
        pinned = bool(commit) and _fetch(commit)
        if not pinned:
            if not _fetch(branch or "HEAD"):
                return {"ok": False, "note": "fetch_failed"}
            note = "branch_tip"

        # Confine the resolved path to the checkout dir.
        abs_path = os.path.realpath(os.path.join(tmp_dir, safe))
        base = os.path.realpath(tmp_dir)
        if not abs_path.startswith(base + os.sep):
            return {"ok": False, "note": "path"}
        if not os.path.isfile(abs_path):
            return {"ok": False, "note": "not_found"}
        if os.path.getsize(abs_path) > 5_000_000:
            return {"ok": False, "note": "too_large"}

        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()

        n = len(lines)
        center = line if line and 1 <= line <= n else 1
        start = max(1, center - radius)
        end = min(n, center + radius)
        snippet = "\n".join(lines[start - 1:end])
        if len(snippet) > max_chars:
            snippet = snippet[:max_chars] + "\n… (truncated)"
        return {"ok": True, "path": safe, "start_line": start, "end_line": end,
                "content": snippet, "note": note}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
# TRIVY FS — dependency + vulnerability scan
# ═══════════════════════════════════════════════════════════════

def _synthesize_nuget_manifests(repo_dir: str) -> int:
    """Trivy ne lit les dépendances NuGet que depuis packages.lock.json,
    *.deps.json ou packages.config. Un projet .NET moderne déclare ses
    PackageReference dans le .csproj sans lockfile → 0 vuln et SBOM vide,
    silencieusement. On synthétise un packages.config par .csproj (versions
    exactes uniquement, ranges/variables MSBuild ignorés) quand aucun
    manifest lisible par trivy n'existe dans le dossier du .csproj.
    Retourne le nombre de fichiers synthétisés."""
    import xml.etree.ElementTree as ET

    import xml.parsers.expat as _expat

    def _safe_parse(path: str) -> ET.ElementTree | None:
        # Contenu non fiable (repo cloné) : DTD interdite (XXE /
        # billion-laughs) via un préflight expat dont les handlers lèvent —
        # comme defusedxml, et contrairement à un test de sous-chaîne sur
        # les octets, insensible à l'encodage (UTF-16…). Taille plafonnée,
        # symlinks ignorés.
        def _reject_dtd(*_a: object) -> None:
            raise ValueError("DTD forbidden in project file")
        try:
            if os.path.islink(path):
                return None
            with open(path, "rb") as fh:
                raw = fh.read(2 * 1024 * 1024)
            guard = _expat.ParserCreate()
            guard.StartDoctypeDeclHandler = _reject_dtd
            guard.EntityDeclHandler = _reject_dtd
            guard.Parse(raw, True)
            return ET.ElementTree(ET.fromstring(raw))
        except (ET.ParseError, _expat.ExpatError, OSError, ValueError):
            logger.warning("Skipping %s: unparseable or forbidden XML", path)
            return None

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]  # strip namespace of legacy csproj

    def _exact(ver: str | None) -> str | None:
        v = (ver or "").strip()
        if not v or any(c in v for c in "$[](),*"):
            return None
        return v

    # Central Package Management: Directory.Packages.props maps id → version
    central: dict[str, str] = {}
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fn in files:
            if fn.lower() != "directory.packages.props":
                continue
            tree = _safe_parse(os.path.join(root, fn))
            if tree is None:
                continue
            for el in tree.iter():
                if _local(el.tag) == "PackageVersion":
                    pid = el.get("Include")
                    v = _exact(el.get("Version"))
                    if pid and v:
                        central[pid.lower()] = v

    created = 0
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        lower = {f.lower() for f in files}
        if "packages.config" in lower or "packages.lock.json" in lower:
            continue
        for fn in files:
            if not fn.endswith(".csproj"):
                continue
            tree = _safe_parse(os.path.join(root, fn))
            if tree is None:
                continue
            pkgs: dict[str, str] = {}
            for el in tree.iter():
                if _local(el.tag) != "PackageReference":
                    continue
                pid = el.get("Include")
                if not pid:
                    continue
                ver = _exact(el.get("Version") or el.get("VersionOverride"))
                if not ver:
                    for child in el:
                        if _local(child.tag) == "Version":
                            ver = _exact(child.text)
                            break
                if not ver:
                    ver = central.get(pid.lower())
                if ver:
                    pkgs[pid] = ver
            if not pkgs:
                continue
            pkgs_el = ET.Element("packages")
            for pid, ver in sorted(pkgs.items()):
                ET.SubElement(pkgs_el, "package", id=pid, version=ver)
            ET.ElementTree(pkgs_el).write(
                os.path.join(root, "packages.config"),
                encoding="utf-8", xml_declaration=True,
            )
            created += 1
            break  # one packages.config per directory
    if created:
        logger.info("Synthesized %d packages.config from .csproj PackageReference", created)
    return created


def run_trivy_fs(repo_dir: str, app_id: str, scan_paths: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    _synthesize_nuget_manifests(repo_dir)
    if scan_paths:
        all_findings: list[dict] = []
        all_sbom: list[dict] = []
        for sp in scan_paths:
            target = _safe_scan_target(repo_dir, sp)
            if not target:
                continue
            f, s = run_trivy_fs(target, app_id, scan_paths=None)
            all_findings.extend(f)
            all_sbom.extend(s)
        return all_findings, all_sbom
    cmd = ["trivy", "fs", "--format", "json", "--scanners", "vuln", "--list-all-pkgs", "--quiet", repo_dir]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if result.returncode != 0 and not result.stdout:
            msg = (result.stderr or "unknown error")[:500]
            logger.warning("trivy fs failed: %s", msg)
            raise RuntimeError(f"trivy fs failed (exit {result.returncode}): {msg}")
        data = json.loads(result.stdout) if result.stdout else {}
    except RuntimeError:
        raise
    except Exception as e:
        logger.error("trivy fs error: %s", e)
        raise RuntimeError(f"trivy fs error: {e}")

    findings = []
    sbom = []
    for target_result in data.get("Results", []):
        target_name = target_result.get("Target", "")
        if target_name.startswith(repo_dir):
            target_name = target_name[len(repo_dir):].lstrip("/")
        target_type = target_result.get("Type", "")
        for vuln in target_result.get("Vulnerabilities", []):
            sev = (vuln.get("Severity") or "UNKNOWN").lower()
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            severity = sev_map.get(sev, "info")
            pkg = vuln.get("PkgName", "")
            ver = vuln.get("InstalledVersion", "")
            cve = vuln.get("VulnerabilityID", "")
            findings.append({
                "scanner": "trivy_fs",
                "type": "cve",
                "severity": severity,
                "title": f"{cve}: {pkg}@{ver}",
                "description": (vuln.get("Description") or "")[:3000],
                "target": f"{target_name} ({pkg}@{ver})",
                "evidence": {
                    "cve": cve,
                    "package": pkg,
                    "installed_version": ver,
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "ecosystem": target_type.lower(),
                    "data_source": vuln.get("DataSource", {}),
                },
                "cve_id": cve,
                "dedup_key": f"trivy_fs|cve|{pkg}@{ver}|{cve}".lower(),
            })

        pkg_list = target_result.get("Packages", [])
        deps_of = {}
        for pkg_info in pkg_list:
            pkg_key = pkg_info.get("ID") or (pkg_info.get("Name", "") + "@" + pkg_info.get("Version", ""))
            for child_id in (pkg_info.get("DependsOn") or []):
                deps_of.setdefault(child_id, []).append(pkg_key)

        for pkg_info in pkg_list:
            pkg_key = pkg_info.get("ID") or (pkg_info.get("Name", "") + "@" + pkg_info.get("Version", ""))
            parents = deps_of.get(pkg_key, [])
            children = pkg_info.get("DependsOn") or []
            sbom.append({
                "package_name": pkg_info.get("Name", ""),
                "version": pkg_info.get("Version", ""),
                "ecosystem": target_type.lower(),
                "license": (", ".join(pkg_info.get("Licenses", [])))[:500] if pkg_info.get("Licenses") else "",
                "direct": not pkg_info.get("Indirect", False),
                "parent_packages": parents[:20],
                "depends_on": children[:50],
            })

    return findings, sbom


# ═══════════════════════════════════════════════════════════════
# TRIVY IMAGE — container image scan
# ═══════════════════════════════════════════════════════════════

def run_trivy_image(image: str, app_id: str, token_encrypted: str = "") -> tuple[list[dict], list[dict]]:
    logger.info("trivy image starting for %s", image)
    cmd = ["trivy", "image", "--format", "json", "--scanners", "vuln",
           "--list-all-pkgs", "--quiet", "--image-src", "remote",
           "--timeout", "15m", image]
    env = {**os.environ}
    if token_encrypted:
        token = decrypt_token(token_encrypted)
        if token:
            # GHCR and most registries accept any non-empty username with a PAT
            env["TRIVY_USERNAME"] = "x-access-token"
            env["TRIVY_PASSWORD"] = token
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT, env=env)
        if result.returncode != 0 and not result.stdout:
            msg = _sanitize_git_error((result.stderr or "unknown error"), image)
            logger.warning("trivy image failed for %s: %s", image, msg)
            raise RuntimeError(f"trivy image failed for {image}: {msg}")
        data = json.loads(result.stdout) if result.stdout else {}
    except RuntimeError:
        raise
    except Exception as e:
        logger.error("trivy image error for %s: %s", image, e)
        raise RuntimeError(f"trivy image error for {image}: {e}")

    findings = []
    sbom = []
    for target_result in data.get("Results", []):
        target_type = target_result.get("Type", "")
        for vuln in target_result.get("Vulnerabilities", []):
            sev = (vuln.get("Severity") or "UNKNOWN").lower()
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            severity = sev_map.get(sev, "info")
            pkg = vuln.get("PkgName", "")
            ver = vuln.get("InstalledVersion", "")
            cve = vuln.get("VulnerabilityID", "")
            findings.append({
                "scanner": "trivy_image",
                "type": "cve",
                "severity": severity,
                "title": f"{cve}: {pkg}@{ver} in {image}",
                "description": (vuln.get("Description") or "")[:3000],
                "target": f"{image} ({pkg}@{ver})",
                "evidence": {
                    "cve": cve,
                    "image": image,
                    "package": pkg,
                    "installed_version": ver,
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "ecosystem": target_type.lower(),
                },
                "cve_id": cve,
                "dedup_key": f"trivy_image|cve|{image}|{pkg}@{ver}|{cve}".lower(),
            })

        pkg_list = target_result.get("Packages", [])
        deps_of = {}
        for pkg_info in pkg_list:
            pkg_key = pkg_info.get("ID") or (pkg_info.get("Name", "") + "@" + pkg_info.get("Version", ""))
            for child_id in (pkg_info.get("DependsOn") or []):
                deps_of.setdefault(child_id, []).append(pkg_key)
        for pkg_info in pkg_list:
            pkg_key = pkg_info.get("ID") or (pkg_info.get("Name", "") + "@" + pkg_info.get("Version", ""))
            parents = deps_of.get(pkg_key, [])
            children = pkg_info.get("DependsOn") or []
            ecosystem = target_type.lower() if target_type else "os"
            sbom.append({
                "package_name": pkg_info.get("Name", ""),
                "version": pkg_info.get("Version", ""),
                "ecosystem": ecosystem,
                "license": (", ".join(pkg_info.get("Licenses", [])))[:500] if pkg_info.get("Licenses") else "",
                "direct": not pkg_info.get("Indirect", False),
                "parent_packages": parents[:20],
                "depends_on": children[:50],
            })

    return findings, sbom


# ═══════════════════════════════════════════════════════════════
# GITLEAKS — secret detection
# ═══════════════════════════════════════════════════════════════

def run_gitleaks(repo_dir: str, app_id: str, scan_paths: list[str] | None = None) -> list[dict]:
    if scan_paths:
        merged: list[dict] = []
        for sp in scan_paths:
            target = _safe_scan_target(repo_dir, sp)
            if not target:
                continue
            merged.extend(run_gitleaks(target, app_id, scan_paths=None))
        return merged
    report_file = os.path.join(tempfile.gettempdir(), f"gitleaks-{uuid.uuid4().hex}.json")
    cmd = ["gitleaks", "detect", "--source", repo_dir, "--report-format", "json",
           "--report-path", report_file, "--no-banner", "--exit-code", "0"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if not os.path.exists(report_file):
            # gitleaks didn't write a report — check if it crashed
            if result.returncode not in (0, 1):
                msg = (result.stderr or "unknown error")[:500]
                raise RuntimeError(f"gitleaks failed (exit {result.returncode}): {msg}")
            return []
        with open(report_file) as f:
            data = json.load(f)
    except RuntimeError:
        raise
    except Exception as e:
        logger.error("gitleaks error: %s", e)
        raise RuntimeError(f"gitleaks error: {e}")
    finally:
        if os.path.exists(report_file):
            os.remove(report_file)

    findings = []
    for leak in data if isinstance(data, list) else []:
        rule = leak.get("RuleID", "unknown")
        filepath = leak.get("File", "")
        if filepath.startswith(repo_dir):
            filepath = filepath[len(repo_dir):].lstrip("/")
        line = leak.get("StartLine", 0)
        findings.append({
            "scanner": "gitleaks",
            "type": "secret",
            "severity": "high",
            "title": f"Secret detected: {rule} in {filepath}",
            "description": f"Rule: {rule}\nFile: {filepath}:{line}\nMatch: {leak.get('Match', '')[:100]}",
            "target": f"{filepath}:{line}",
            "evidence": {
                "rule": rule,
                "file": filepath,
                "line": line,
                "commit": leak.get("Commit", ""),
                "author": leak.get("Author", ""),
            },
            "dedup_key": f"gitleaks|secret|{filepath}:{line}|{rule}".lower(),
        })
    return findings


# ═══════════════════════════════════════════════════════════════
# SEMGREP — SAST
# ═══════════════════════════════════════════════════════════════

def run_semgrep(repo_dir: str, app_id: str, scan_paths: list[str] | None = None) -> list[dict]:
    if scan_paths:
        merged: list[dict] = []
        for sp in scan_paths:
            target = _safe_scan_target(repo_dir, sp)
            if not target:
                continue
            merged.extend(run_semgrep(target, app_id, scan_paths=None))
        return merged
    cmd = ["semgrep", "scan", "--json", "--config", "p/default", "--config", "p/owasp-top-ten",
           "--config", "p/javascript", "--config", "p/typescript", "--config", "p/python", repo_dir]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT,
                                env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
        logger.info("semgrep exit=%d stdout=%d stderr=%d", result.returncode, len(result.stdout or ""), len(result.stderr or ""))
        if not result.stdout or not result.stdout.strip():
            msg = (result.stderr or "unknown error")[:500]
            logger.warning("semgrep produced no stdout. stderr: %s", msg)
            raise RuntimeError(f"semgrep failed (exit {result.returncode}): {msg}")
        data = json.loads(result.stdout)
    except RuntimeError:
        raise
    except json.JSONDecodeError as e:
        logger.error("semgrep JSON parse error: %s — stdout[:200]: %s", e, (result.stdout or "")[:200])
        raise RuntimeError(f"semgrep JSON parse error: {e}")
    except Exception as e:
        logger.error("semgrep error: %s", e)
        raise RuntimeError(f"semgrep error: {e}")

    findings = []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for match in data.get("results", []):
        rule_id = match.get("check_id", "unknown")
        filepath = match.get("path", "")
        if filepath.startswith(repo_dir):
            filepath = filepath[len(repo_dir):].lstrip("/")
        line = match.get("start", {}).get("line", 0)
        severity = sev_map.get(match.get("extra", {}).get("severity", ""), "medium")
        msg = match.get("extra", {}).get("message", "")
        findings.append({
            "scanner": "semgrep",
            "type": "sast",
            "severity": severity,
            "title": f"{rule_id}",
            "description": msg[:3000],
            "target": f"{filepath}:{line}",
            "evidence": {
                "rule_id": rule_id,
                "file": filepath,
                "line": line,
                "lines": match.get("extra", {}).get("lines", "")[:500],
                "metadata": match.get("extra", {}).get("metadata", {}),
            },
            "dedup_key": f"semgrep|sast|{filepath}:{line}|{rule_id}".lower(),
        })
    return findings


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATION
# ═══════════════════════════════════════════════════════════════

SCANNERS = {
    "trivy_fs": run_trivy_fs,
    "trivy_image": run_trivy_image,
    "gitleaks": run_gitleaks,
    "semgrep": run_semgrep,
}
