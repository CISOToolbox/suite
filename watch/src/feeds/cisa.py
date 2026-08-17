"""CISA Cybersecurity Advisories — US national CERT RSS.

Single consolidated feed at /cybersecurity-advisories/all.xml. Covers
both joint advisories (AA…) and vendor advisories republished by CISA.
Used by the threat-watch matcher for English-language narrative on
campaigns, supply-chain attacks, and KEV additions.

Severity: "high" by default — CISA only publishes advisories worth
operator attention. The KEV catalogue stays in its own dedicated
adapter (``feeds.kev``) because it has a different shape (CSV/JSON
with explicit CVE ids, no RSS).
"""
from __future__ import annotations

import re

from .rss_base import SimpleRSSFeed


class CISAFeed(SimpleRSSFeed):
    source = "cisa"
    default_severity = "high"
    # CISA joint advisory ids look like "AA24-123A" — capture when present
    # so duplicate AA-IDs across the RSS pagination collapse on upsert.
    id_regex = re.compile(r"\bAA\d{2}-\d+[A-Z]?\b")
    urls = [
        ("all", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ]
