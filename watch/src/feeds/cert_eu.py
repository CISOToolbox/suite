"""CERT-EU threat-intelligence advisories.

CERT-EU (the CERT of the EU institutions) publishes weekly
``CITAR`` threat-intel bulletins + occasional ``Security Advisory``
posts. Severity is left at ``medium`` because the publication mixes
informational summaries and actionable advisories; the keyword matcher
is what surfaces the relevant ones to the digest.
"""
from __future__ import annotations

import re

from .rss_base import SimpleRSSFeed


class CERTEUFeed(SimpleRSSFeed):
    source = "cert_eu"
    default_severity = "medium"
    # CERT-EU advisory ids look like "CERT-EU-SA2024-123" — capture
    # when present so paginated reposts collapse on upsert.
    id_regex = re.compile(r"\bCERT-EU-[A-Z]+\d{4}-\d+\b", re.IGNORECASE)
    urls = [
        ("threat_intel", "https://cert.europa.eu/publications/threat-intelligence-rss"),
        ("security_advisories", "https://cert.europa.eu/publications/security-advisories-rss"),
    ]
