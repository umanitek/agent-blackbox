"""urlscan.io as a source — the level-3 "visit", bought not built (§03.5, F-012, D22).

A domain or link is opened ONCE by urlscan.io in its browser, with
``unlisted`` visibility (not on urlscan's public pages), and the result is
read back. Two outputs:

* a :class:`SourceVerdict` — urlscan's overall verdict says malicious → FOUND
  (``reference_id`` = the scan's uuid); says not malicious → CLEAN; anything
  else → UNAVAILABLE;
* :class:`UrlscanScan` — the structured observations the Evidence Extractor
  (``curate/lab/extractor.py``, L3) consumes as its ``urlscan`` section:
  ``page.domain``, ``lists.domains|ips|hashes`` and ``verdicts.overall.brands``,
  type-checked and nothing else. :meth:`UrlscanScan.lab_output` is the raw lab
  output ``extract(job, raw)`` takes; the job's key uses :data:`IMAGE_SHA256`.

Submit once, poll later (State): a check submits and answers UNAVAILABLE
(urlscan asks callers to wait 10–30 s); a check of the same target at least
:data:`FIRST_POLL_AFTER_SECONDS` later polls the stored scan instead of
submitting again. So a beat never blocks for a visit, and a re-check never
spends a second scan. A scan with no result after :data:`GIVE_UP_AFTER_SECONDS`
is dropped (the next check may submit again); a finished scan is kept for
:data:`RESULT_TTL_SECONDS`. State is in memory: a restart may scan once more.

Every non-definite answer is UNAVAILABLE and never kept as an answer (LES-011,
LES-028): no API key, a refused submission (HTTP 400 for a blocked domain,
429 over quota), a result still scanning (HTTP 404) or deleted (410), and a
200 answer that carries an error ``status`` / ``message`` or did not reach a page.

Privacy (F-023): the URL is sent to a third party, so its query string,
fragment and user info are stripped first (the lab job store's own rule).

Terms: the free tier allows 1,000 unlisted scans a day → a 40-an-hour bucket
(960 a day), and every check — a poll included — spends a token, so the
bucket can only undershoot. urlscan is not in the §03.3 terms table: until the
founder clears it, it is never cited (``citable=False``, needs founder).

The API key lives in ``credentials.json`` under :data:`API_KEY_NAME`, on the
Umanitek node only (F-056: keyed sources are never queried from the lab).

Usage::

    source = UrlscanSource()
    source.check("ioc:domain:wallet-claim.example")   # UNAVAILABLE: submitted
    source.check("ioc:domain:wallet-claim.example")   # a beat later: FOUND / CLEAN
    raw = source.scan("ioc:domain:wallet-claim.example").lab_output()
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from ...kernel import threat_ids
from ..lab import strip_query
from ..service.evidence import Lookup
from .client import HttpClient, JsonObject, UrllibClient
from .credentials import key_for
from .protocol import REUSE_NEEDS_FOUNDER, SourceTerms, SourceVerdict

NAME = "urlscan"
API_KEY_NAME = "urlscan"
SUBMIT_ENDPOINT = "https://urlscan.io/api/v1/scan/"
RESULT_ENDPOINT = "https://urlscan.io/api/v1/result/{uuid}/"
VISIBILITY = "unlisted"
#: Level 3 has no lab image; this stands in for one in the job key. A change of
#: urlscan API version or visibility is a new "image", so old evidence is not reused.
IMAGE_SHA256 = hashlib.sha256(f"urlscan.io/api/v1:{VISIBILITY}".encode("ascii")).hexdigest()
LEVEL = 3

FIRST_POLL_AFTER_SECONDS = 10
GIVE_UP_AFTER_SECONDS = 10 * 60
RESULT_TTL_SECONDS = 24 * 60 * 60
#: Scans tracked at once (pending + finished); a full table refuses new submissions.
MAX_TRACKED_SCANS = 500
#: Entries kept per observation list; the extractor caps (and notes) what it keeps.
MAX_LIST_ENTRIES = 1_000
TERMS = SourceTerms(citable=False, reuse_state=REUSE_NEEDS_FOUNDER, limit_requests=40, limit_seconds=60 * 60)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_LISTS = ("domains", "ips", "hashes")


_default_key = key_for(API_KEY_NAME)   # the credentials file, read when asked


@dataclass(frozen=True)
class UrlscanScan:
    """One finished visit: the scan ``uuid``, the ``url`` urlscan opened, when
    we submitted it and read the result (UTC epoch seconds), the ``verdict``,
    and the ``observations`` — the extractor's ``urlscan`` section, shaped
    ``{"page": {"domain": str}, "lists": {"domains": [str], "ips": [str],
    "hashes": [str]}, "verdicts": {"overall": {"brands": [str]}}}``."""

    uuid: str
    url: str
    submitted_at: int
    finished_at: int
    verdict: SourceVerdict
    observations: Mapping[str, Any]

    def lab_output(self) -> dict[str, Any]:
        """The raw lab output ``extractor.extract(job, raw)`` reads for a level-3 job."""
        return {"started_at": self.submitted_at, "finished_at": self.finished_at, "urlscan": self.observations}


@dataclass(frozen=True)
class _Pending:
    uuid: str
    url: str
    submitted_at: float


class UrlscanSource:
    """The urlscan.io Strategy; *client*, *key* and *clock* are injectable for tests."""

    name = NAME
    terms = TERMS

    def __init__(self, client: Optional[HttpClient] = None, *, key: Callable[[], Optional[str]] = _default_key,
                 clock: Callable[[], float] = time.time) -> None:
        self._client = client or UrllibClient()
        self._key = key
        self._clock = clock
        self._lock = threading.Lock()
        self._scans: dict[str, _Pending | UrlscanScan] = {}

    def applies(self, identifier: str) -> bool:
        return visit_url(identifier) is not None

    def check(self, identifier: str) -> SourceVerdict:
        url = visit_url(identifier)
        if url is None:
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=NAME)
        api_key = self._key()
        if not api_key:
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
        now = self._clock()
        with self._lock:
            self._forget_stale(now)
            tracked = self._scans.get(url)
            if isinstance(tracked, UrlscanScan):
                return tracked.verdict
            if isinstance(tracked, _Pending):
                return self._poll(tracked, api_key, now)
            self._submit(url, api_key, now)
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)   # submitted; the result comes on a later check

    def scan(self, identifier: str) -> Optional[UrlscanScan]:
        """The finished scan for *identifier*, or None (never submitted, still scanning, or forgotten)."""
        url = visit_url(identifier)
        with self._lock:
            tracked = self._scans.get(url) if url else None
            return tracked if isinstance(tracked, UrlscanScan) else None

    def _submit(self, url: str, api_key: str, now: float) -> None:
        if len(self._scans) >= MAX_TRACKED_SCANS:
            return
        answer = self._client.post(SUBMIT_ENDPOINT, headers={"API-Key": api_key},
                                   json_body={"url": url, "visibility": VISIBILITY})
        uuid = answer.get("uuid") if answer is not None else None
        if isinstance(uuid, str) and _UUID.match(uuid):
            self._scans[url] = _Pending(uuid, url, now)

    def _poll(self, pending: _Pending, api_key: str, now: float) -> SourceVerdict:
        if now - pending.submitted_at < FIRST_POLL_AFTER_SECONDS:
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
        answer = self._client.get(RESULT_ENDPOINT.format(uuid=pending.uuid), headers={"API-Key": api_key})
        if answer is None:
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)   # still scanning (404) or could not tell
        verdict = _verdict(answer, pending.uuid)
        if verdict.status is Lookup.UNAVAILABLE:
            del self._scans[pending.url]   # an unusable result is not kept; a later check may scan again
            return verdict
        self._scans[pending.url] = UrlscanScan(pending.uuid, pending.url, int(pending.submitted_at), int(now),
                                               verdict, _observations(answer))
        return verdict

    def _forget_stale(self, now: float) -> None:
        def stale(entry: _Pending | UrlscanScan) -> bool:
            if isinstance(entry, _Pending):
                return now - entry.submitted_at > GIVE_UP_AFTER_SECONDS
            return now - entry.finished_at > RESULT_TTL_SECONDS
        self._scans = {url: entry for url, entry in self._scans.items() if not stale(entry)}


def visit_url(identifier: str) -> Optional[str]:
    """The URL urlscan should open for *identifier*: an ``ioc:url:`` without
    its query, fragment or user info, or ``https://<domain>/`` for an
    ``ioc:domain:``. None for anything else."""
    ioc_type, value = threat_ids.parse_ioc_identifier(identifier) or ("", "")
    if ioc_type == "url":
        return strip_query(value)
    if ioc_type == "domain":
        return f"https://{value}/"
    return None


def _verdict(result: JsonObject, uuid: str) -> SourceVerdict:
    """urlscan's overall verdict, but only from a result that reached a page and carries no error."""
    if not isinstance(result, Mapping) or "message" in result or result.get("status", 200) != 200:
        return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
    page = result.get("page")
    if not isinstance(page, Mapping) or not isinstance(page.get("domain"), str) or not page["domain"]:
        return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)   # the visit never landed on a page
    malicious = _mapping(_mapping(result.get("verdicts")).get("overall")).get("malicious")
    if malicious is True:
        return SourceVerdict(Lookup.FOUND, source=NAME, reference_id=uuid)
    if malicious is False:
        return SourceVerdict(Lookup.CLEAN, source=NAME)
    return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)


def _observations(result: JsonObject) -> dict[str, Any]:
    """The extractor's ``urlscan`` section: only the typed fields it reads, strings only, bounded."""
    lists = _mapping(result.get("lists"))
    return {
        "page": {"domain": result["page"]["domain"]},
        "lists": {name: _strings(lists.get(name)) for name in _LISTS},
        "verdicts": {"overall": {"brands": _strings(_mapping(_mapping(result.get("verdicts")).get("overall")).get("brands"))}},
    }


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _strings(value: object) -> list[str]:
    return [entry for entry in value if isinstance(entry, str)][:MAX_LIST_ENTRIES] if isinstance(value, list) else []
