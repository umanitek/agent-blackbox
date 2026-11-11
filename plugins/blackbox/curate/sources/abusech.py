"""abuse.ch — URLhaus, ThreatFox and MalwareBazaar as sources (§03.3, F-004, F-005, D20).

Three Strategies sharing one :class:`AbuseChFetcher`, which owns the
Auth-Key and the 5-minute rule:

* :class:`UrlhausSource` — ``ioc:url:`` via ``/v1/url/``; ``ioc:domain:`` and
  ``ioc:ip:`` via ``/v1/host/``.
* :class:`ThreatFoxSource` — ``ioc:domain|url|ip|hash:`` via ``search_ioc``
  (exact match). An IOC last seen more than :data:`THREATFOX_EXPIRY_DAYS` ago
  counts as expired, matching ThreatFox's own 6-month expiry — not listed.
* :class:`MalwareBazaarSource` — ``ioc:hash:`` (MD5, SHA-1, SHA-256) via ``get_info``.

The 5-minute rule: abuse.ch regenerates its data every 5 minutes and asks
that nothing is fetched more often, so every answer (each source's "dump" of
what it knows about one indicator) is kept for :data:`DUMP_MIN_INTERVAL_SECONDS`
and the same request inside that window is served from memory. A request
that could not tell (no answer, or an error status) is not kept, so it may be retried.

Without an Auth-Key (``credentials.json`` entry :data:`AUTH_KEY_NAME`, one key
for every abuse.ch platform) every check is UNAVAILABLE.

Terms (D20, NEEDS FOUNDER): fair use for non-commercial; commercial use may
need a Spamhaus subscription; no derivative works without consent. Until the
founder records consent or a subscription these sources are LOOK-UP ONLY —
``citable=False``, never cited in a published row. abuse.ch publishes no
query rate limit; the bucket is our own courtesy cap.

Usage::

    fetcher = AbuseChFetcher()
    urlhaus, threatfox, bazaar = (cls(fetcher) for cls in (UrlhausSource, ThreatFoxSource, MalwareBazaarSource))
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone, UTC
from typing import Callable, Dict, Optional, Tuple

from ...kernel import threat_ids
from ..service.evidence import Lookup
from .client import HttpClient, JsonObject, UrllibClient
from .credentials import CredentialsError, load_credentials
from .protocol import REUSE_LOOKUP_ONLY, SourceTerms, SourceVerdict

AUTH_KEY_NAME = "abusech"
DUMP_MIN_INTERVAL_SECONDS = 5 * 60
THREATFOX_EXPIRY_DAYS = 180
TERMS = SourceTerms(citable=False, reuse_state=REUSE_LOOKUP_ONLY, limit_requests=60, limit_seconds=60)

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"

#: ``query_status`` values meaning "asked, and not listed" (ThreatFox says
#: ``no_result``, URLhaus ``no_results``, MalwareBazaar ``hash_not_found``).
_NOT_LISTED = frozenset({"no_result", "no_results", "hash_not_found"})
#: Only these answers are kept for 5 minutes; an error status (a wrong Auth-Key,
#: an illegal search term) is "could not tell" and may be retried at once.
_DEFINITE = _NOT_LISTED | {"ok"}
_THREATFOX_TYPES = frozenset({"domain", "url", "ip", "hash"})
_BAZAAR_HASH_LENGTHS = frozenset({32, 40, 64})
_THREATFOX_TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def _default_key() -> Optional[str]:
    try:
        return load_credentials().get(AUTH_KEY_NAME)
    except CredentialsError:
        return None   # a file we may not use is the same as no key: could not tell


class AbuseChFetcher:
    """One abuse.ch request, sent with the Auth-Key; a definite answer is kept for 5 minutes.

    ``fetch`` returns the answer's JSON object, or ``None`` when there is no
    key or the request could not tell. *key*, *client* and *clock* are
    injectable for tests.
    """

    def __init__(self, client: Optional[HttpClient] = None, *, key: Callable[[], Optional[str]] = _default_key,
                 clock: Callable[[], float] = time.time) -> None:
        self._client = client or UrllibClient()
        self._key = key
        self._clock = clock
        self._lock = threading.Lock()
        self._answers: dict[str, tuple[float, JsonObject]] = {}

    def fetch(self, url: str, *, form: Optional[dict[str, str]] = None,
              json_body: Optional[JsonObject] = None) -> Optional[JsonObject]:
        auth_key = self._key()
        if not auth_key:
            return None
        request_key = json.dumps([url, form, json_body], sort_keys=True)
        now = self._clock()
        with self._lock:
            kept = self._answers.get(request_key)
            if kept is not None and now - kept[0] < DUMP_MIN_INTERVAL_SECONDS:
                return kept[1]
        answer = self._client.post(url, headers={"Auth-Key": auth_key}, form=form, json_body=json_body)
        if answer is not None and answer.get("query_status") in _DEFINITE:
            with self._lock:
                self._answers = {k: v for k, v in self._answers.items() if now - v[0] < DUMP_MIN_INTERVAL_SECONDS}
                self._answers[request_key] = (now, answer)
        return answer


def _verdict(source: str, answer: Optional[JsonObject], reference_id: str) -> SourceVerdict:
    """Map an abuse.ch answer: ``ok`` with a reference → FOUND, a not-listed
    status → CLEAN, anything else (no answer, an error status) → UNAVAILABLE."""
    status = answer.get("query_status") if answer is not None else None
    if status == "ok" and reference_id:
        return SourceVerdict(Lookup.FOUND, source=source, reference_id=reference_id)
    if status in _NOT_LISTED:
        return SourceVerdict(Lookup.CLEAN, source=source)
    return SourceVerdict(Lookup.UNAVAILABLE, source=source)


def _first_id(records: object) -> str:
    if isinstance(records, list) and records and isinstance(records[0], dict):
        return str(records[0].get("id") or "")
    return ""


class UrlhausSource:
    """URLhaus: is this URL, domain or IP listed as a malware distribution site?"""

    name = "urlhaus"
    terms = TERMS

    def __init__(self, fetcher: AbuseChFetcher) -> None:
        self._fetcher = fetcher

    def check(self, identifier: str) -> SourceVerdict:
        parts = threat_ids.parse_ioc_identifier(identifier)
        if parts is None or parts[0] not in ("url", "domain", "ip"):
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=self.name)
        ioc_type, value = parts
        if ioc_type == "url":
            answer = self._fetcher.fetch(URLHAUS_URL_ENDPOINT, form={"url": value})
            reference = str(answer.get("id") or "") if answer else ""
        else:
            answer = self._fetcher.fetch(URLHAUS_HOST_ENDPOINT, form={"host": value})
            reference = _first_id(answer.get("urls")) if answer else ""
        return _verdict(self.name, answer, reference)


class ThreatFoxSource:
    """ThreatFox: is this indicator a live (under 6 months old) IOC?"""

    name = "threatfox"
    terms = TERMS

    def __init__(self, fetcher: AbuseChFetcher, *, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._fetcher = fetcher
        self._now = now

    def check(self, identifier: str) -> SourceVerdict:
        parts = threat_ids.parse_ioc_identifier(identifier)
        if parts is None or parts[0] not in _THREATFOX_TYPES:
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=self.name)
        answer = self._fetcher.fetch(THREATFOX_ENDPOINT, json_body={
            "query": "search_ioc", "search_term": parts[1], "exact_match": True})
        if answer is None or answer.get("query_status") != "ok":
            return _verdict(self.name, answer, "")
        records = answer.get("data")
        if not isinstance(records, list) or not records:
            return SourceVerdict(Lookup.UNAVAILABLE, source=self.name)
        cutoff = self._now() - timedelta(days=THREATFOX_EXPIRY_DAYS)
        for record in records:
            seen = _last_seen(record)
            if seen is None:
                return SourceVerdict(Lookup.UNAVAILABLE, source=self.name)   # a listing we cannot age: could not tell
            if seen >= cutoff:
                return SourceVerdict(Lookup.FOUND, source=self.name, reference_id=str(record.get("id") or ""))
        return SourceVerdict(Lookup.CLEAN, source=self.name)   # every listing has expired


def _last_seen(record: object) -> Optional[datetime]:
    """The newer of an IOC's ``first_seen`` / ``last_seen`` (UTC), or None when
    the record is malformed or carries no readable date."""
    if not isinstance(record, dict) or not record.get("id"):
        return None
    seen = []
    for field in ("first_seen", "last_seen"):
        text = record.get(field)
        if not text:
            continue
        try:
            seen.append(datetime.strptime(str(text), _THREATFOX_TIME_FORMAT).replace(tzinfo=UTC))
        except ValueError:
            return None
    return max(seen) if seen else None


class MalwareBazaarSource:
    """MalwareBazaar: is this file hash a known malware sample?"""

    name = "malwarebazaar"
    terms = TERMS

    def __init__(self, fetcher: AbuseChFetcher) -> None:
        self._fetcher = fetcher

    def check(self, identifier: str) -> SourceVerdict:
        parts = threat_ids.parse_ioc_identifier(identifier)
        if parts is None or parts[0] != "hash" or len(parts[1]) not in _BAZAAR_HASH_LENGTHS:
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=self.name)
        answer = self._fetcher.fetch(MALWAREBAZAAR_ENDPOINT, form={"query": "get_info", "hash": parts[1]})
        records = answer.get("data") if answer else None
        reference = str(records[0].get("sha256_hash") or "") if (
            isinstance(records, list) and records and isinstance(records[0], dict)) else ""
        return _verdict(self.name, answer, reference)
