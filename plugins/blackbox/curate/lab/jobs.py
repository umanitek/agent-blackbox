"""Lab jobs — what the curator asked the lab to test, and where each request stands
(proposal §03.5, F-034, F-057).

Patterns: Command (a frozen :class:`LabJob` is the request) + State (each job
moves through :class:`LabJobState` by the transition table ``_NEXT``; any
other move raises).

* One job per key = (threat digest, level, image hash). A re-request of a known
  key returns the stored record (and its evidence), never a second job.
* Bounded: at most :data:`CAPACITY` jobs wait or run at once. A full store
  REFUSES the request; the refusal is not stored, so the queue item stays
  "awaiting lab", keeps flagging and is asked again later (wait-and-flag,
  never drop).
* A running job past its level's deadline reads COULD_NOT_TELL.
* Data protection (F-023): an identifier is stored with any URL query string
  and fragment stripped; the requester is stored only as the peer id its
  request was signed under, kept like the share ledger (until the operator
  erases it — :meth:`LabJobStore.forget_requester`).

Usage::

    store = LabJobStore()
    record = store.request(identifier, level=2, image_sha256=image, lane=Lane.GRADUATION, requested_by=peer_id)
    if record.state is LabJobState.REFUSED: ...         # queue full: keep flagging
    for record in store.queued(): store.start(record.job.key)
    store.complete(key, evidence)                       # RUNNING -> DONE
    store.evidence(store.get(key))                      # the stored Evidence
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional
from urllib.parse import urlsplit, urlunsplit

from ...kernel.bounded_files import atomic_write, file_lock
from .. import keys
from ..queue import Lane
from . import evidence_schema
from .evidence_schema import Evidence

logger = logging.getLogger(__name__)

#: At most this many jobs wait or run at once (§03.5: the lab queue is bounded at 500).
CAPACITY = 500
#: Seconds a RUNNING job may take before it reads COULD_NOT_TELL (level 4: 5 min, F-034).
DEADLINE_SECONDS = {1: 120, 2: 120, 3: 300, 4: 300}
#: A libp2p peer id (base58: ``12D3KooW…`` Ed25519 or legacy ``Qm…``).
_PEER_ID = re.compile(r"^(12D3KooW|Qm)[1-9A-HJ-NP-Za-km-z]{38,60}$")
_JOBS_FILE = "jobs.jsonl"
#: Where the URL inside an identifier begins: its scheme followed by ``://``.
_URL_START = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


class LabJobError(ValueError):
    """A bad request or a move the job's state does not allow."""


class LabJobState(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    COULD_NOT_TELL = "could-not-tell"
    REFUSED = "refused"


#: The State table: where each state may move. DONE and COULD_NOT_TELL are final;
#: REFUSED is never stored.
_NEXT = {
    LabJobState.QUEUED: frozenset({LabJobState.RUNNING, LabJobState.COULD_NOT_TELL}),
    LabJobState.RUNNING: frozenset({LabJobState.DONE, LabJobState.COULD_NOT_TELL}),
}


@dataclass(frozen=True)
class LabJob:
    """The request (Command): test *identifier* at *level* in image *key*'s hash.

    ``key`` is :func:`evidence_schema.job_key`; ``requested_by`` a peer id;
    ``requested_at`` UTC epoch seconds."""

    key: str
    identifier: str
    level: int
    lane: Lane
    requested_by: str
    requested_at: float


@dataclass(frozen=True)
class LabJobRecord:
    """A job and where it stands. ``evidence_sha256`` names the stored evidence
    of a DONE job (``<lab dir>/evidence/<sha256>.json``)."""

    job: LabJob
    state: LabJobState
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    evidence_sha256: Optional[str] = None


def strip_query(identifier: str) -> str:
    """*identifier* without a URL query string, fragment or user name/password
    (they can carry personal data). Works on a bare URL and on a prefixed one
    (``url:https://…``); an identifier without ``://`` is returned unchanged."""
    url_start = _URL_START.search(identifier)
    if url_start is None:
        return identifier
    prefix, url = identifier[:url_start.start()], identifier[url_start.start():]
    scheme, netloc, path, _query, _fragment = urlsplit(url)
    return prefix + urlunsplit((scheme, netloc.rpartition("@")[2], path, "", ""))


def threat_digest(identifier: str) -> str:
    """sha256 hex of the stored (query-stripped) identifier."""
    return hashlib.sha256(strip_query(identifier).encode("utf-8")).hexdigest()


class LabJobStore:
    """Every lab job this curator node asked for, at ``<curate home>/lab/jobs.jsonl``.

    Several stores share the file (the controller, ``lab status``, the console's metrics), so:
    a READ never writes (an expired RUNNING job reads COULD_NOT_TELL without being saved), and
    every CHANGE re-reads the file under its cross-process lock before rewriting it atomically
    (one JSON record per line) — no store writes back a stale snapshot over another's job."""

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time,
                 capacity: int = CAPACITY) -> None:
        self._path = path or (keys.curate_home() / "lab" / _JOBS_FILE)
        self._evidence_dir = self._path.parent / "evidence"
        self._clock = clock
        self._capacity = capacity
        self._lock = threading.Lock()
        self._records: dict[str, LabJobRecord] = self._load()

    def request(self, identifier: str, *, level: int, image_sha256: str, lane: Lane,
                requested_by: str) -> LabJobRecord:
        """Queue a job, or return the stored record of the same key, or a
        (not stored) REFUSED record when the store is full."""
        if not _PEER_ID.match(requested_by or ""):
            raise LabJobError("requested_by must be the signed peer id of the requester")
        stored_identifier = strip_query(identifier)
        try:
            key = evidence_schema.job_key(threat_digest(stored_identifier), level, image_sha256)
        except evidence_schema.EvidenceError as exc:
            raise LabJobError(str(exc)) from None
        job = LabJob(key, stored_identifier, level, lane, requested_by, self._clock())
        with self._changing():
            known = self._settled(key)
            if known is not None:
                return known
            if len(self._open()) >= self._capacity:
                return LabJobRecord(job, LabJobState.REFUSED)
            return self._put(LabJobRecord(job, LabJobState.QUEUED))

    def get(self, key: str) -> Optional[LabJobRecord]:
        with self._lock:
            self._records = self._load()
            return self._settled(key)

    def queued(self) -> list[LabJobRecord]:
        """QUEUED jobs in work order: lane first, then oldest request."""
        with self._lock:
            self._records = self._load()
            waiting = [r for r in self._records.values() if r.state is LabJobState.QUEUED]
        return sorted(waiting, key=lambda r: (r.job.lane.value, r.job.requested_at))

    def records(self) -> list[LabJobRecord]:
        """Every stored job, each settled (a RUNNING job past its deadline reads
        COULD_NOT_TELL) — what the controller polls and its metrics count."""
        with self._lock:
            self._records = self._load()
            return [self._settled(key) for key in list(self._records)]

    def start(self, key: str) -> LabJobRecord:
        with self._changing():
            return self._move(key, LabJobState.RUNNING, started_at=self._clock())

    def complete(self, key: str, evidence: Evidence) -> LabJobRecord:
        """RUNNING → DONE, storing *evidence* (whose ``job_key`` must be *key*)."""
        if evidence.job_key != key:
            raise LabJobError("the evidence belongs to another job")
        text = evidence_schema.to_json(evidence)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._changing():
            self._evidence_dir.mkdir(parents=True, exist_ok=True)
            # Content-addressed: an existing file already holds these exact bytes.
            if not (self._evidence_dir / f"{digest}.json").exists():
                _write_atomic(self._evidence_dir / f"{digest}.json", text + "\n")
            return self._move(key, LabJobState.DONE, finished_at=self._clock(), evidence_sha256=digest)

    def could_not_tell(self, key: str) -> LabJobRecord:
        with self._changing():
            return self._move(key, LabJobState.COULD_NOT_TELL, finished_at=self._clock())

    def evidence(self, record: Optional[LabJobRecord]) -> Optional[Evidence]:
        """The stored evidence of a DONE *record*, validated on read; else None."""
        if record is None or record.evidence_sha256 is None:
            return None
        path = self._evidence_dir / f"{record.evidence_sha256}.json"
        return evidence_schema.validate_evidence(json.loads(path.read_text(encoding="utf-8-sig")))

    def forget_requester(self, peer_id: str) -> int:
        """Erase *peer_id* from every job (data-subject erasure); the count changed."""
        with self._changing():
            mine = [r for r in self._records.values() if r.job.requested_by == peer_id]
            for record in mine:
                job = dataclasses.replace(record.job, requested_by="")
                self._records[job.key] = dataclasses.replace(record, job=job)
            if mine:
                self._save()
            return len(mine)

    # -- internals (callers hold the lock) ------------------------------------

    @contextlib.contextmanager
    def _changing(self) -> Iterator[None]:
        """For a change: this store's lock and the file's cross-process lock, with the
        records re-read from the file, so another store's newer jobs are kept."""
        with self._lock, file_lock(self._path.with_name(self._path.name + ".lock")):
            self._records = self._load()
            yield

    def _open(self) -> list[LabJobRecord]:
        return [r for r in self._records.values() if r.state in (LabJobState.QUEUED, LabJobState.RUNNING)]

    def _settled(self, key: str) -> Optional[LabJobRecord]:
        """The record for *key* as it stands now: a RUNNING job past its deadline reads
        COULD_NOT_TELL. Nothing is saved (a read never writes); the next change saves it."""
        record = self._records.get(key)
        if record is None or record.state is not LabJobState.RUNNING:
            return record
        if self._clock() - (record.started_at or 0) <= DEADLINE_SECONDS[record.job.level]:
            return record
        return dataclasses.replace(record, state=LabJobState.COULD_NOT_TELL, finished_at=self._clock())

    def _move(self, key: str, state: LabJobState, **changes) -> LabJobRecord:
        record = self._settled(key)   # a RUNNING job past its deadline cannot complete late
        if record is None:
            raise LabJobError("no such lab job")
        if state not in _NEXT.get(record.state, frozenset()):
            raise LabJobError(f"a {record.state.value} job cannot become {state.value}")
        return self._put(dataclasses.replace(record, state=state, **changes))

    def _put(self, record: LabJobRecord) -> LabJobRecord:
        self._records[record.job.key] = record
        self._save()
        return record

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lines = (json.dumps(_record_to_mapping(r), sort_keys=True) for r in self._records.values())
        _write_atomic(self._path, "".join(line + "\n" for line in lines))

    def _load(self) -> dict[str, LabJobRecord]:
        records: dict[str, LabJobRecord] = {}
        try:
            text = self._path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            return records
        for number, line in enumerate(text.splitlines(), 1):
            try:
                record = _record_from_mapping(json.loads(line))
            except (ValueError, KeyError, TypeError) as exc:
                logger.warning("blackbox lab: skipped unreadable job line %d of %s: %s", number, self._path, exc)
                continue
            records[record.job.key] = record
        return records


def _record_to_mapping(record: LabJobRecord) -> dict:
    job = record.job
    return {
        "key": job.key, "identifier": job.identifier, "level": job.level, "lane": job.lane.name,
        "requested_by": job.requested_by, "requested_at": job.requested_at, "state": record.state.value,
        "started_at": record.started_at, "finished_at": record.finished_at,
        "evidence_sha256": record.evidence_sha256,
    }


def _record_from_mapping(row: dict) -> LabJobRecord:
    """One stored line back to a record. The key, level and evidence digest are
    re-checked: a tampered file must not name a path outside the evidence folder,
    nor a level the deadline table does not know."""
    evidence_sha256 = row.get("evidence_sha256")
    if not evidence_schema.is_job_key(row["key"]) or not (
            evidence_sha256 is None or evidence_schema.is_sha256(evidence_sha256)):
        raise ValueError("malformed key or evidence digest")
    if int(row["level"]) != int(row["key"].split(":")[1]):
        raise ValueError("level does not match the key")
    job = LabJob(str(row["key"]), strip_query(str(row["identifier"])), int(row["level"]), Lane[row["lane"]],
                 str(row["requested_by"]), float(row["requested_at"]))
    return LabJobRecord(job, LabJobState(row["state"]), row.get("started_at"), row.get("finished_at"),
                        evidence_sha256)


def _write_atomic(path: Path, text: str) -> None:
    """Write *text* to *path* as a private (0600) file, torn-free (the kernel's one write)."""
    atomic_write(path, text, mode=0o600)
