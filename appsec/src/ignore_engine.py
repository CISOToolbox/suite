"""Ignore-rules matching engine.

Called during findings upsert to auto-triage findings that match an
active ignore rule. A rule matches when ALL its criteria match (AND)
and the finding's application is in the rule's app scope (or the rule
is global).
"""
from __future__ import annotations

import fnmatch
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import IgnoreRule

logger = logging.getLogger("appsec-ignore")


async def load_rules(db: AsyncSession, app_id) -> list[IgnoreRule]:
    """Load all enabled rules that apply to the given app (+ global)."""
    result = await db.execute(
        select(IgnoreRule).where(IgnoreRule.enabled == True)  # noqa: E712
    )
    all_rules = result.scalars().all()
    # Filter: keep rules where application_ids is empty (global) or contains app_id.
    app_str = str(app_id) if app_id else ""
    return [
        r for r in all_rules
        if not r.application_ids  # empty = global
        or app_str in [str(a) for a in r.application_ids]
    ]


def _match_single(finding: dict, ctype: str, cvalue: str) -> bool:
    """Test if a single criterion matches a finding."""
    cv = (cvalue or "").strip()
    if not cv:
        return False

    if ctype == "cve_id":
        fv = (finding.get("cve_id") or "").upper()
        return fnmatch.fnmatch(fv, cv.upper())

    if ctype == "package":
        ev = finding.get("evidence") or {}
        pkg = ev.get("package", "") if isinstance(ev, dict) else ""
        ver = ev.get("installed_version", "") if isinstance(ev, dict) else ""
        full = f"{pkg}@{ver}" if ver else pkg
        if not full:
            full = finding.get("target", "")
        return fnmatch.fnmatch(full.lower(), cv.lower())

    if ctype == "scanner_rule":
        scanner = finding.get("scanner", "")
        ev = finding.get("evidence") or {}
        rule_id = (ev.get("rule_id") or ev.get("rule") or "") if isinstance(ev, dict) else ""
        combined = f"{scanner}:{rule_id}" if rule_id else scanner
        return fnmatch.fnmatch(combined.lower(), cv.lower())

    if ctype == "target_pattern":
        return fnmatch.fnmatch((finding.get("target") or "").lower(), cv.lower())

    if ctype == "severity":
        return (finding.get("severity") or "").lower() == cv.lower()

    if ctype == "ecosystem":
        ev = finding.get("evidence") or {}
        eco = ev.get("ecosystem", "") if isinstance(ev, dict) else ""
        return fnmatch.fnmatch(eco.lower(), cv.lower())

    return False


def matches_rule(finding: dict, rule: IgnoreRule) -> bool:
    """A rule matches when ALL its criteria match (AND logic)."""
    criteria = rule.criteria or []
    if not criteria:
        return False
    return all(
        _match_single(finding, c.get("type", ""), c.get("value", ""))
        for c in criteria
        if isinstance(c, dict)
    )


def apply_ignore_rules(findings: list[dict], rules: list[IgnoreRule]) -> tuple[list[dict], int]:
    """Apply rules to a batch of findings. Returns (findings, ignored_count).

    Matched findings get status=false_positive with a triage_notes
    referencing the rule. They stay in the list so they appear in the
    UI (greyed out) and can be un-ignored if the rule is later disabled.
    """
    if not rules:
        return findings, 0
    ignored = 0
    for f in findings:
        for r in rules:
            if matches_rule(f, r):
                criteria_desc = " AND ".join(
                    f"{c.get('type')}={c.get('value')}" for c in (r.criteria or []) if isinstance(c, dict)
                )
                f["status"] = "false_positive"
                f["triage_notes"] = f"[auto-ignore] {criteria_desc}: {r.reason}"
                ignored += 1
                break
    return findings, ignored
