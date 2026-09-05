"""AppSec AI endpoints.

The shared /api/ai proxy (provider registry, key/settings management,
/complete, /runtime, /config, /keys, /validate-key, the LLM dispatch) lives in
src/ai_proxy_common.py. Only the finding-triage métier — NVD enrichment,
methodology prompt and the analyze endpoint — is here.
"""
from __future__ import annotations

import datetime
import json

import httpx
from fastapi import Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.ai_proxy_common import (
    _check_ai_access,
    _check_rate_limit,
    _parse_json_lax,
    _provider_complete,
    _runtime_provider_model,
    make_ai_router,
)
from src.auth import get_current_user
from src.database import get_db
from src.models import User

# Common /api/ai endpoints; the domain endpoint below is appended to it.
router = make_ai_router()


async def _nvd_lookup(cve_id: str) -> str:
    """Fetch verified NVD data for a CVE id and return a prompt-ready block.

    Runs server-side: the strict module CSP (connect-src 'self') blocks the
    browser from reaching services.nvd.nist.gov, so this enrichment only
    works once it is done here rather than in AppSec_app.js.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
            )
        if not r.is_success:
            return ""
        vulns = r.json().get("vulnerabilities") or []
        if not vulns:
            return ""
        cve = vulns[0].get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")
        metrics = cve.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        cvss = cvss_list[0] if cvss_list else None
        refs = ", ".join(x.get("url", "") for x in (cve.get("references") or [])[:3])
        block = (
            f"\n\nNVD verified data for {cve_id}:\n"
            f"Description: {desc}\n"
            f"Published: {cve.get('published', 'N/A')}\n"
        )
        if cvss:
            cd = cvss.get("cvssData", {})
            block += (
                f"CVSS: {cd.get('baseScore')} ({cd.get('baseSeverity')})\n"
                f"Vector: {cd.get('vectorString')}\n"
            )
        return block + f"References: {refs}"
    except (httpx.HTTPError, ValueError, KeyError, IndexError):
        return ""


_LANG_NAMES = {"fr": "French", "en": "English"}


def _finding_analysis_system(lang: str = "fr") -> str:
    """System prompt for the AppSec finding triage — methodology owned here.
    `lang` controls the language of the prose fields (summary/remediation);
    JSON keys and enum values stay in English so the response parses."""
    today = datetime.date.today().isoformat()
    year = today[:4]
    lang_name = _LANG_NAMES.get((lang or "fr").lower(), "French")
    return (
        "You are a senior application security engineer performing triage on findings "
        "from automated security scanners (Trivy, Gitleaks, Semgrep). "
        f"Today's date is {today}. CVE identifiers with year {year} or earlier are valid and published. "
        "The scanner databases are up-to-date — trust the CVE data provided in the finding evidence. "
        "Do NOT dismiss a CVE as fake or hallucinated based on its year alone. "
        "If the finding includes a CVE ID, use the NVD data provided below (if available) as ground truth. "
        "If a source-code excerpt is provided, base your false-positive verdict and "
        "remediation on the actual code (data flow, reachability, sanitization) rather "
        "than the scanner message alone. "
        "If the analyst provides additional context, weigh it in your verdict. "
        f"Write the \"summary\" and \"remediation\" values in {lang_name}. "
        "Keep the JSON keys and all enum values in English. "
        "Analyze the finding and respond in JSON with: "
        '{"is_probable_false_positive": bool, "confidence": "high|medium|low", '
        '"severity_recommendation": "critical|high|medium|low|info", '
        '"summary": "one paragraph analysis", "remediation": "step-by-step fix", '
        '"references": ["url1","url2"]}'
    )


class FindingAnalyzeRequest(BaseModel):
    finding_id: str
    lang: str = "fr"
    context: str = ""
    deep: bool = False


class FindingAnalyzeResponse(BaseModel):
    is_probable_false_positive: bool = False
    confidence: str = ""
    severity_recommendation: str = ""
    summary: str = ""
    remediation: str = ""
    references: list[str] = []
    deep_used: bool = False
    deep_note: str = ""


@router.post("/appsec/analyze-finding", response_model=FindingAnalyzeResponse)
async def analyze_finding(body: FindingAnalyzeRequest,
                          user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """Triage one AppSec finding: false-positive verdict, severity
    recommendation, summary and remediation. The finding is loaded from the
    DB by id (server-authoritative); the methodology prompt and the NVD
    enrichment are built server-side.
    """
    import uuid as _uuid
    from src.models import Application, Finding

    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")

    try:
        fid = _uuid.UUID(str(body.finding_id))
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid finding id")
    res = await db.execute(select(Finding).where(Finding.id == fid))
    f = res.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    provider, model = await _runtime_provider_model(db)
    nvd_block = await _nvd_lookup(f.cve_id) if f.cve_id else ""

    user_prompt = "Finding to triage:\n" + json.dumps({
        "scanner": f.scanner,
        "type": f.type,
        "severity": f.severity,
        "title": f.title,
        "description": (f.description or "")[:2000],
        "target": f.target,
        "cve_id": f.cve_id,
        "evidence": f.evidence,
    }, indent=2, ensure_ascii=False, default=str) + nvd_block

    # Analyst-provided context (untrusted free text) — bounded, appended verbatim.
    ctx = (body.context or "").strip()[:2000]
    if ctx:
        user_prompt += "\n\nAdditional context from the analyst:\n" + ctx

    # Deep analysis: pull the referenced source file at the scanned commit and
    # include a code window. Best-effort — a failure never blocks the triage.
    deep_used = False
    deep_note = ""
    if body.deep:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        rel_path = str(ev.get("file") or "")
        try:
            line_no = int(ev.get("line") or 0)
        except (TypeError, ValueError):
            line_no = 0
        if not rel_path:
            deep_note = "no_file"
        else:
            app = (await db.execute(
                select(Application).where(Application.id == f.application_id)
            )).scalar_one_or_none()
            if not app or not (app.repo_url or ""):
                deep_note = "no_repo"
            else:
                from src.scanners import fetch_file_window
                win = await run_in_threadpool(
                    fetch_file_window, app.repo_url, app.repo_branch or "main",
                    app.last_scan_commit or "", app.repo_token_encrypted or "",
                    rel_path, line_no,
                )
                if win.get("ok"):
                    deep_used = True
                    deep_note = win.get("note") or ""
                    user_prompt += (
                        f"\n\nSource code excerpt from {win['path']} "
                        f"(lines {win['start_line']}-{win['end_line']}, "
                        f"finding at line {line_no}):\n```\n{win['content']}\n```"
                    )
                else:
                    deep_note = win.get("note") or "fetch_failed"

    raw = await _provider_complete(db, _finding_analysis_system(body.lang), user_prompt, provider, model)
    parsed = _parse_json_lax(raw)
    refs = [str(x) for x in (parsed.get("references") or [])
            if str(x).startswith(("http://", "https://"))]
    return FindingAnalyzeResponse(
        is_probable_false_positive=bool(parsed.get("is_probable_false_positive")),
        confidence=str(parsed.get("confidence") or ""),
        severity_recommendation=str(parsed.get("severity_recommendation") or ""),
        summary=str(parsed.get("summary") or ""),
        remediation=str(parsed.get("remediation") or ""),
        references=refs,
        deep_used=deep_used,
        deep_note=deep_note,
    )
