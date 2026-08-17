"""CISA ICS Advisories — industrial control system advisories.

Distinct from :mod:`feeds.cisa` so operators can subscribe to ICS-only
threat watch (the ICS feed is high-volume but very specific to OT/SCADA
deployments). Items are tagged ``source = "cisa_ics"`` so a topic like
"siemens" or "schneider" fires here independently of the generic CISA
stream.
"""
from __future__ import annotations

import re

from .rss_base import SimpleRSSFeed


class CISAICSFeed(SimpleRSSFeed):
    source = "cisa_ics"
    default_severity = "high"
    # ICS advisories use IDs like "ICSA-24-123-01" — capture so the
    # upsert key stays stable when the feed paginates.
    id_regex = re.compile(r"\bICSA-\d{2}-\d{3}-\d{2}\b")
    urls = [
        ("ics", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
    ]
