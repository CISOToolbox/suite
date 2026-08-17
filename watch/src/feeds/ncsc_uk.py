"""NCSC-UK news + threat advisories.

The UK National Cyber Security Centre publishes a single consolidated
RSS that mixes news, threat reports and advisories. We treat every
item at ``medium`` severity — the keyword matcher decides whether a
topic like "ransomware" or "supply chain" makes it digest-worthy.
"""
from __future__ import annotations

from .rss_base import SimpleRSSFeed


class NCSCUKFeed(SimpleRSSFeed):
    source = "ncsc_uk"
    default_severity = "medium"
    urls = [
        ("all", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
    ]
