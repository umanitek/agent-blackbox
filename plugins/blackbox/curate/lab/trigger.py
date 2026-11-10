"""The lab trigger — which queue items earn a lab job, and at which levels
(proposal §03.5, F-033, F-034).

The rule, :func:`lab_trigger` (a pure function the beat's submit step calls
for every NEW queue item): an item that NO outside source lists, and either

(a) ≥ 2 counted reporter clusters with a partner organisation among them
    (two distinct partner ``org``s, or a graduated independent reporter plus
    a partner), or
(b) one partner-cluster report plus a curator's typed request
    (``blackbox curate lab <identifier>``, logged as a human act).

Two graduated independents with no partner do not fire: the lab spends a
paid, rate-limited budget (urlscan's 40 an hour), and a curator who wants
such an item tested can still ask for it once a partner reports it. At
launch only (b) can fire — the two counted partners are one reporting
cluster until a second organisation reports (D17, D12 revised).

Sources answer in three ways (LES-011), folded by :func:`sources_say` into
the one verdict enum, ``service.evidence.Lookup``: FOUND — a source lists the
threat (no lab job: the listing is the evidence); CLEAN — every source
answered "not listed" (the lab may run); UNAVAILABLE — a source could not
tell (no job yet: a busy source is never read as "not listed"; the next beat
asks again).

Level order, :func:`due_levels`: levels 1–2 (look, read) first; 3 (visit)
and 4 (run) only once every first level this node runs has settled (DONE or
COULD_NOT_TELL). Level 3 is the urlscan source's visit, due only when the
registry's own urlscan instance holds a finished scan of the item; level 4
runs only on the KVM host, i.e. only when :class:`LabSetup` lists an image
for it.

No source code here: the lab package holds no source credentials and imports
nothing from ``curate/sources``. The caller injects ``scan_ready`` built on
the registry's own instance — ``next(s for s in SOURCES if isinstance(s,
UrlscanSource))``, never a new ``UrlscanSource``: scan state lives in memory
per instance, so a second one would submit again and spend another scan from
the 40-an-hour bucket — and maps level 3 to ``urlscan.IMAGE_SHA256``.

Wait-and-flag, :func:`submit_candidate`: one LabJob per (threat digest,
level, image hash) — re-asking returns the stored record. A full job store
refuses; the item is then AWAITING_LAB, keeps its stage and keeps flagging,
and the next beat asks again. Nothing is dropped.

The human act, :class:`LabRequests`: a typed request is one append-only
row in ``<curate home>/lab/requests.jsonl`` holding the threat digest and
the consent code — never the identifier's text, which can be a prompt
(an injection pattern) or a command line (an escalation shape).

This module is imported by path (``curate.lab.trigger``), not from the
``curate.lab`` package surface: ``curate.service`` loads ``curate.lab`` at
import time, and this module reads ``curate.service.evidence``.

Usage (the beat's submit step)::

    requested = LabRequests().requested_digests()
    candidate = LabCandidate(item, partner_clusters=c.partner, independent_clusters=c.established,
                             sources=sources_say(result.verdicts),
                             curator_requested=threat_digest(item.identifier) in requested)
    submission = submit_candidate(candidate, controller.store, setup, submit=controller.submit,
                                  scan_ready=lambda identifier: registry_urlscan.scan(identifier) is not None)
    if submission.status is SubmissionStatus.AWAITING_LAB: ...   # report it; the item keeps flagging
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import AbstractSet, Callable, FrozenSet, Iterable, Mapping, Optional, Protocol, Tuple

from ...kernel.bounded_files import append_line, read_jsonl
from .. import keys
from ..queue import Lane, QueueItem
from ..service.evidence import Lookup, OwnCheck
from . import evidence_schema
from .jobs import DEADLINE_SECONDS, LabJobRecord, LabJobState, LabJobStore, strip_query, threat_digest

#: Levels that run first, on every lab host (§03.5: look, read).
FIRST_LEVELS = frozenset({1, 2})
#: The urlscan.io visit (``sources.urlscan.LEVEL``); urlscan runs it, not a lab host.
VISIT_LEVEL = 3
#: The act a typed request is logged as.
TYPED_REQUEST_ACT = "lab-request"
_REQUESTS_FILE = "requests.jsonl"
_SETTLED = frozenset({LabJobState.DONE, LabJobState.COULD_NOT_TELL})
#: Level 2 reads, and level 4 installs or runs, package and skill code; level 4 also
#: tries an injection pattern against a test agent.
_CODE_PREFIXES = ("dep:", "skill:")
_RUN_PREFIXES = (*_CODE_PREFIXES, "injection:")


def sources_say(verdicts: Iterable[OwnCheck]) -> Lookup:
    """Fold every source's verdict on one item: any FOUND → FOUND; no answer
    at all, or any UNAVAILABLE → UNAVAILABLE; else (CLEAN or not applicable
    everywhere) → CLEAN."""
    statuses = [verdict.status for verdict in verdicts]
    if Lookup.FOUND in statuses:
        return Lookup.FOUND
    if not statuses or Lookup.UNAVAILABLE in statuses:
        return Lookup.UNAVAILABLE
    return Lookup.CLEAN


@dataclass(frozen=True)
class LabCandidate:
    """One NEW queue item as the trigger sees it: the ``item``, its counted
    clusters (``community`` stages' ``Clusters.partner`` and ``.established``),
    what the sources said (:func:`sources_say`), and whether a curator's typed request is on file."""

    item: QueueItem
    partner_clusters: int
    independent_clusters: int
    sources: Lookup
    curator_requested: bool = False


@dataclass(frozen=True)
class TriggerDecision:
    fires: bool
    why: str


def lab_trigger(candidate: LabCandidate) -> TriggerDecision:
    """Whether *candidate* earns a lab job (the rule in the module doc)."""
    if candidate.sources is Lookup.FOUND:
        return TriggerDecision(False, "a source already lists it: no lab job")
    if candidate.sources is not Lookup.CLEAN:
        return TriggerDecision(False, "the sources could not tell yet: no lab job until they answer")
    partners = candidate.partner_clusters
    if partners >= 1 and partners + candidate.independent_clusters >= 2:
        return TriggerDecision(True, "two counted reporter clusters, a partner among them")
    if partners >= 1 and candidate.curator_requested:
        return TriggerDecision(True, "a partner-cluster report and a curator's typed request")
    if candidate.curator_requested:
        return TriggerDecision(False, "a typed request needs a partner-cluster report behind it")
    return TriggerDecision(False, "one counted cluster: a curator may request the lab")


@dataclass(frozen=True)
class LabSetup:
    """What this node's labs run. ``images`` maps a level to the sha256 of the
    clean image serving it — a level without an image is not run here (level 4
    is listed only once the KVM host is up; level 3, the urlscan visit, maps
    to ``sources.urlscan.IMAGE_SHA256``). ``requested_by`` — this node's signed peer id."""

    images: Mapping[int, str]
    requested_by: str

    def __post_init__(self) -> None:
        if not set(self.images) <= set(DEADLINE_SECONDS):
            raise ValueError(f"lab levels are {sorted(DEADLINE_SECONDS)}")
        if not all(evidence_schema.is_sha256(image) for image in self.images.values()):
            raise ValueError("every lab image is named by its sha256")


def _applies(level: int, identifier: str) -> bool:
    if level == 1:
        return True
    if level == 2:
        return identifier.startswith(_CODE_PREFIXES)
    if level == VISIT_LEVEL:
        return True     # due only with a finished scan, and urlscan scans only a domain or a link
    return level == 4 and identifier.startswith(_RUN_PREFIXES)


def due_levels(identifier: str, setup: LabSetup, settled: AbstractSet[int], *, scan_ready: bool) -> tuple[int, ...]:
    """The levels to request now for *identifier*, in order. *settled* — the
    levels whose jobs are DONE or COULD_NOT_TELL; *scan_ready* — the registry's
    urlscan instance holds a finished scan of it."""
    runnable = [level for level in sorted(setup.images) if _applies(level, identifier)]
    first = [level for level in runnable if level in FIRST_LEVELS]
    if not set(first) <= set(settled):
        return tuple(first)
    later = [level for level in runnable if level not in FIRST_LEVELS and (level != VISIT_LEVEL or scan_ready)]
    return tuple(first + later)


class SubmissionStatus(Enum):
    NOT_TRIGGERED = "not-triggered"
    SUBMITTED = "submitted"
    AWAITING_LAB = "awaiting-lab"


@dataclass(frozen=True)
class LabSubmission:
    """What the submit step did for one item. ``item`` is returned unchanged:
    a lab request never alters an item's stage or enforcement (it keeps flagging)."""

    item: QueueItem
    status: SubmissionStatus
    why: str
    records: tuple[LabJobRecord, ...] = ()


class JobRequest(Protocol):
    """``LabJobStore.request`` or ``LabController.submit`` (which also sends the job at once)."""

    def __call__(self, identifier: str, *, level: int, image_sha256: str, lane: Lane,
                 requested_by: str) -> LabJobRecord: ...


def submit_candidate(candidate: LabCandidate, store: LabJobStore, setup: LabSetup, *,
                     scan_ready: Callable[[str], bool], submit: Optional[JobRequest] = None) -> LabSubmission:
    """The beat's submit step for one item: apply :func:`lab_trigger`, then
    request each due level (:func:`due_levels`) through *submit* (default
    ``store.request``). *scan_ready* — whether the registry's urlscan instance
    holds a finished scan of an identifier (see the module doc). A refusal (full store) stops the step: AWAITING_LAB."""
    item = candidate.item
    decision = lab_trigger(candidate)
    if not decision.fires:
        return LabSubmission(item, SubmissionStatus.NOT_TRIGGERED, decision.why)
    levels = due_levels(item.identifier, setup, _settled_levels(item.identifier, store, setup),
                        scan_ready=scan_ready(item.identifier))
    if not levels:
        return LabSubmission(item, SubmissionStatus.NOT_TRIGGERED, "no lab on this node runs this kind of threat")
    request = submit or store.request
    records = []
    for level in levels:
        record = request(item.identifier, level=level, image_sha256=setup.images[level], lane=item.lane,
                         requested_by=setup.requested_by)
        if record.state is LabJobState.REFUSED:
            return LabSubmission(item, SubmissionStatus.AWAITING_LAB,
                                 "the lab queue is full: awaiting lab, still flagging; asked again next beat",
                                 tuple(records))
        records.append(record)
    return LabSubmission(item, SubmissionStatus.SUBMITTED, decision.why, tuple(records))


def _settled_levels(identifier: str, store: LabJobStore, setup: LabSetup) -> frozenset[int]:
    digest = threat_digest(identifier)
    settled = set()
    for level, image in setup.images.items():
        record = store.get(evidence_schema.job_key(digest, level, image))
        if record is not None and record.state in _SETTLED:
            settled.add(level)
    return frozenset(settled)


class LabRequests:
    """The human-act log of typed lab requests: append-only, mode 0600, local
    only. A row is ``{"ts", "act", "threat_digest", "code"}`` — never the
    identifier's text and never who typed it (the node's own operator)."""

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (keys.curate_home() / "lab" / _REQUESTS_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    def record(self, identifier: str, *, code: str) -> None:
        """Log that a curator typed *code* to request a lab test of *identifier*."""
        row = {"ts": self._clock(), "act": TYPED_REQUEST_ACT, "threat_digest": threat_digest(strip_query(identifier)),
               "code": code}
        with self._lock:
            append_line(self._path, json.dumps(row, sort_keys=True), mode=0o600)

    def requested_digests(self) -> frozenset[str]:
        """Threat digests a curator has requested (unreadable lines are skipped)."""
        digests = set()
        with self._lock:
            rows = read_jsonl(self._path)
        for row in rows:
            if row.get("act") != TYPED_REQUEST_ACT:
                continue
            if evidence_schema.is_sha256(row.get("threat_digest")):
                digests.add(row["threat_digest"])
        return frozenset(digests)


__all__ = [
    "FIRST_LEVELS", "TYPED_REQUEST_ACT", "VISIT_LEVEL", "JobRequest", "LabCandidate", "LabRequests", "LabSetup",
    "LabSubmission", "SubmissionStatus", "TriggerDecision", "due_levels", "lab_trigger", "sources_say",
    "submit_candidate",
]
