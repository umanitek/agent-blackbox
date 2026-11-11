"""ScamSniffer scam-database as a source — LOOK-UP ONLY (§03.3, F-004, D20).

Checks one identifier against ScamSniffer's open blacklists on GitHub:

* ``ioc:domain:`` and the host of an ``ioc:url:`` → ``blacklist/domains.json``;
* an EVM ``ioc:wallet:`` / ``ioc:contract:`` address → ``blacklist/address.json``.

Matching is EXACT (a listed ``evil.example`` says nothing about
``login.evil.example``): a FOUND answer must be definite. Listed → FOUND,
not listed → CLEAN, a list we could not fetch or read → UNAVAILABLE.

Both files are JSON lists of strings (domains.json is ~9 MB, 357k entries on
2026-10-11). Each list is fetched at most once per :data:`SNAPSHOT_TTL_SECONDS`
(the publisher refreshes daily) and held in memory only — never written to
disk, never republished: the list is evidence we look things up in, not a feed
we mirror. A failed fetch is not retried for :data:`RETRY_AFTER_SECONDS`, so a
beat of 100 look-ups never downloads 100 × 9 MB.

Terms (§03.3 table): GPL-3.0 on a data repo, the open data lags 7 days, no
dispute route. The legal view on GPL-over-data is NEEDS FOUNDER (D20), so
``citable=False``. Should it be cleared, a cited row must name the source and
the date: every FOUND verdict already carries it as ``reference_id`` —
``"blacklist/domains.json@2026-10-11"`` (the list file and the UTC day we read it).

Usage::

    verdict = ScamSnifferSource().check("ioc:domain:wallet-claim.example")
    verdict.reference_id   # "blacklist/domains.json@2026-10-11" when FOUND
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import timezone
from typing import Callable, Dict, FrozenSet, Optional, Tuple
from urllib.parse import urlsplit

from ...kernel.health import utc_day
from ...kernel import threat_ids
from ..service.evidence import Lookup
from .client import HttpClient, UrllibClient
from .protocol import REUSE_LOOKUP_ONLY, SourceTerms, SourceVerdict

NAME = "scamsniffer"
RAW_BASE = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/"
DOMAINS_FILE = "blacklist/domains.json"
ADDRESSES_FILE = "blacklist/address.json"
#: domains.json was 9 MB on 2026-10-11; room to grow, but never an unbounded read.
MAX_LIST_BYTES = 64_000_000
SNAPSHOT_TTL_SECONDS = 24 * 60 * 60
RETRY_AFTER_SECONDS = 5 * 60
#: Checks run against the in-memory list; the bucket is our own courtesy cap on look-ups.
TERMS = SourceTerms(citable=False, reuse_state=REUSE_LOOKUP_ONLY, limit_requests=600, limit_seconds=60)

#: ioc type → the list file that answers it.
_FILE_FOR_TYPE = {"domain": DOMAINS_FILE, "url": DOMAINS_FILE, "wallet": ADDRESSES_FILE, "contract": ADDRESSES_FILE}


@dataclass(frozen=True)
class _Snapshot:
    """One list as read on ``day`` (UTC ISO date) at epoch ``fetched_at``."""

    entries: frozenset[str]
    day: str
    fetched_at: float


class ScamSnifferSource:
    """The ScamSniffer Strategy; *client* and *clock* are injectable for tests."""

    name = NAME
    terms = TERMS

    def __init__(self, client: Optional[HttpClient] = None, *, clock: Callable[[], float] = time.time) -> None:
        self._client = client or UrllibClient()
        self._clock = clock
        self._lock = threading.Lock()
        self._snapshots: dict[str, _Snapshot] = {}
        self._failed_at: dict[str, float] = {}

    def check(self, identifier: str) -> SourceVerdict:
        target = _lookup_target(identifier)
        if target is None:
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=NAME)
        list_file, value = target
        snapshot = self._snapshot(list_file)
        if snapshot is None:
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
        if value in snapshot.entries:
            return SourceVerdict(Lookup.FOUND, source=NAME, reference_id=f"{list_file}@{snapshot.day}")
        return SourceVerdict(Lookup.CLEAN, source=NAME)

    def _snapshot(self, list_file: str) -> Optional[_Snapshot]:
        """The current list, fetching it when missing or a day old; None when it could not be read."""
        now = self._clock()
        with self._lock:
            # One lock across the fetch: concurrent beats share one download, never start two.
            current = self._snapshots.get(list_file)
            if current is not None and now - current.fetched_at < SNAPSHOT_TTL_SECONDS:
                return current
            if now - self._failed_at.get(list_file, float("-inf")) < RETRY_AFTER_SECONDS:
                return None
            entries = _entries(self._client.get(RAW_BASE + list_file, headers={}, max_bytes=MAX_LIST_BYTES))
            if entries is None:
                # A stale list is not served: its CLEAN would be cached for another 24 h on top of its age.
                self._snapshots.pop(list_file, None)
                self._failed_at[list_file] = now
                return None
            day = utc_day(now)
            self._snapshots[list_file] = snapshot = _Snapshot(entries, day, now)
            return snapshot


def _entries(answer: object) -> Optional[frozenset[str]]:
    """The list's entries lowercased, or None unless the answer is a non-empty JSON list of strings."""
    if not isinstance(answer, list) or not answer or not all(isinstance(entry, str) for entry in answer):
        return None
    return frozenset(entry.strip().lower() for entry in answer)


def _lookup_target(identifier: str) -> Optional[tuple[str, str]]:
    """``(list file, value to match)`` for an identifier ScamSniffer can answer, else None."""
    parsed = threat_ids.parse_ioc_identifier(identifier)
    if parsed is None or parsed[0] not in _FILE_FOR_TYPE:
        return None
    ioc_type, value = parsed
    if ioc_type == "url":
        value = urlsplit(value).hostname or ""
    elif ioc_type in ("wallet", "contract") and not threat_ids.EVM_ADDRESS_RE.fullmatch(value):
        return None   # ScamSniffer lists EVM addresses only
    return (_FILE_FOR_TYPE[ioc_type], value.lower()) if value else None
