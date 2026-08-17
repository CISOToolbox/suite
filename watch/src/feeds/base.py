"""Feed adapter base classes + the shared AlertCandidate dataclass.

A feed adapter is a small async object that knows how to:
  1. fetch the delta of new/modified advisories since a cursor;
  2. translate each advisory into the Watch-canonical AlertCandidate.

The scheduler is responsible for persisting the candidates and
updating FeedState. Adapters never touch the database directly.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator


class FeedError(RuntimeError):
    """Raised by adapters when an upstream call fails recoverably.

    The scheduler treats FeedError as "try again next tick" — the
    feed is not disabled, ``last_error`` is recorded.
    """


@dataclass
class AlertCandidate:
    """Normalised advisory record produced by feed adapters.

    Fields map 1:1 to columns on :class:`watch.models.Alert`. Any
    extra source-specific data goes into ``raw``.

    ``affected`` is a list of dicts shaped like::

        {"cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
         "version_range": "<3.0.0", "vendor": "openssl",
         "product": "openssl"}

        {"purl": "pkg:npm/lodash", "version_range": ">=0,<4.17.21"}

        {"vendor": "fortinet", "product": "fortigate"}  # keyword-only

    The matcher consumes this list directly.
    """
    source: str
    external_id: str
    title: str = ""
    summary: str = ""
    severity: str = "unknown"
    cvss_score: float | None = None
    cvss_vector: str = ""
    epss_score: float | None = None
    kev_listed: bool = False
    published_at: datetime | None = None
    modified_at: datetime | None = None
    references: list[str] = field(default_factory=list)
    affected: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class FeedAdapter(abc.ABC):
    """Abstract base class for vulnerability feed adapters."""

    #: Stable identifier persisted in feed_state.source / alerts.source.
    source: str

    #: Minimum interval between successful fetches, in seconds. The
    #: scheduler clamps to TICK_SECONDS so a 60s interval still only
    #: runs every tick (default 15 min).
    interval_seconds: int = 900

    #: Network timeout per HTTP request.
    request_timeout: float = 30.0

    @abc.abstractmethod
    async def fetch_delta(self, since: datetime | None, cursor: str) -> "FetchResult":
        """Return the new + modified advisories since ``since`` / ``cursor``.

        Implementations should be idempotent — calling fetch_delta
        twice with the same arguments must yield the same candidates.
        """


@dataclass
class FetchResult:
    """Output of :meth:`FeedAdapter.fetch_delta`.

    ``candidates`` may be an async iterator so paginated feeds can
    stream results without buffering the full delta. ``next_cursor``
    is opaque to the scheduler — only the adapter interprets it.
    """
    candidates: AsyncIterator[AlertCandidate]
    next_cursor: str = ""
