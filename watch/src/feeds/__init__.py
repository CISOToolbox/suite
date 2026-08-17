"""Feed adapter registry.

Each adapter implements :class:`FeedAdapter` and yields
:class:`AlertCandidate` records normalised to the Watch schema.

The scheduler iterates over ``FEEDS`` on every tick, respecting each
feed's ``next_due_at`` cooldown so noisy sources (NVD's near-real-time
modified-window) can be polled more often than slow ones (CERT-FR RSS).
"""
from __future__ import annotations

from .base import AlertCandidate, FeedAdapter, FeedError
from .nvd import NVDFeed
from .osv import OSVFeed
from .kev import KEVFeed
from .certfr import CERTFRFeed
from .cisa import CISAFeed
from .cisa_ics import CISAICSFeed
from .cert_eu import CERTEUFeed
from .ncsc_uk import NCSCUKFeed

# Registry. Adding a new feed = appending to this list.
FEEDS: list[FeedAdapter] = [
    NVDFeed(),
    OSVFeed(),
    KEVFeed(),
    CERTFRFeed(),
    CISAFeed(),
    CISAICSFeed(),
    CERTEUFeed(),
    NCSCUKFeed(),
]


def feed_by_source(source: str) -> FeedAdapter | None:
    for f in FEEDS:
        if f.source == source:
            return f
    return None


__all__ = [
    "AlertCandidate",
    "FeedAdapter",
    "FeedError",
    "FEEDS",
    "feed_by_source",
]
