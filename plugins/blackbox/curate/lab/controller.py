"""LabController — the only code that talks to the lab (proposal §03.5, D28, F-024, F-034).

Run as beat steps on curator A: :meth:`LabController.submit` after admission,
:meth:`LabController.poll` before verdicts. One poll sends every QUEUED job to
the lab, asks after every RUNNING one, and for a finished run collects the raw
output, turns it into :class:`Evidence` with the injected extractor (L3, pure
functions), signs it with the LAB CONTROLLER's own key through the signing
choke point (``CurateContext.sign(EvidenceDraft)``) and stores it at
``<lab dir>/evidence/<sha256>.json`` with the envelope beside it
(``<sha256>.envelope.json``).

Rules held here:

* Per-job deadline (``jobs.DEADLINE_SECONDS``, level 4: 5 min) → COULD_NOT_TELL
  (the store settles it).
* At most :data:`MAX_ATTEMPTS` lab runs per job (the first + 2 retries); the
  count survives restarts (``<lab dir>/attempts.json``). An unreachable lab
  costs no attempt — the lab never ran the job; the deadline bounds the wait.
* The lab can LIE, so a lab-only verdict is capped by
  :func:`lab_only_verdict_may_block`.
* No source API keys: this package never imports ``curate/sources/credentials``.

Patterns: Facade over the job store, the transport, the extractor and the
signing choke point; the extractor is a Strategy (any ``Extractor`` callable).

Usage::

    controller = LabController(ctx, lab_key, LabTransport(url), extractor.extract)
    controller.submit(identifier, level=2, image_sha256=image, lane=Lane.GRADUATION, requested_by=peer_id)
    controller.poll()                                  # every beat
    signed = controller.evidence(key)                  # verified, or None
    controller.metrics().scale_step(over_an_hour_for)  # the scale rule
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ...kernel import signing, threat_ids
from .. import keys
from ..context import LAB_EVIDENCE_STATEMENT, CurateContext, EvidenceDraft
from ..queue import Lane
from . import evidence_schema
from .evidence_schema import Evidence, EvidenceError
from .jobs import WAITING_STATES, LabJob, LabJobRecord, LabJobState, LabJobStore, _write_atomic
from .transport import LabAnswer, LabOutcome, LabTransport

logger = logging.getLogger(__name__)

#: Lab runs per job: the first one and at most 2 retries (§03.5).
MAX_ATTEMPTS = 3
#: Distinct, independent lab hosts that must agree before a lab-only verdict of a
#: block-tier type may block (F-024). Until Lab 2 exists this is never reached.
INDEPENDENT_LAB_HOSTS_TO_BLOCK = 2
#: Categories (``threat_ids.category_for``) whose lab-only verdicts are block-tier
#: types: packages and skills; a file fingerprint is an ``ioc:hash:`` identifier.
_BLOCK_TIER_CATEGORIES = frozenset({"dependency", "skill"})
_FINGERPRINT_PREFIX = "ioc:hash:"

#: The scale rule (F-034), as metrics thresholds: the oldest job older than an
#: hour for a day → one more worker; older than four hours → a second lab host.
ADD_WORKER_QUEUE_AGE_SECONDS = 3_600
ADD_WORKER_SUSTAINED_SECONDS = 86_400
ADD_LAB_HOST_QUEUE_AGE_SECONDS = 4 * 3_600
_HOUR = 3_600

_ATTEMPTS_FILE = "attempts.json"
_ENVELOPE_SUFFIX = ".envelope.json"

#: The Evidence Extractor (L3): raw lab output for a job → typed Evidence; raises EvidenceError.
Extractor = Callable[[LabJob, Mapping[str, Any]], Evidence]


class ScaleStep(Enum):
    ADD_WORKER = "add-worker"
    ADD_LAB_HOST = "add-lab-host"


@dataclass(frozen=True)
class LabMetrics:
    """Lab health from the job store: jobs finished in the last hour, jobs waiting
    or running, and the age (seconds) of the oldest of those (0 when none)."""

    jobs_per_hour: int
    queue_depth: int
    oldest_job_age: float

    def scale_step(self, over_an_hour_for: float) -> Optional[ScaleStep]:
        """The scale rule. *over_an_hour_for* — seconds the oldest job age has
        stayed above an hour (the caller tracks it across beats)."""
        if self.oldest_job_age > ADD_LAB_HOST_QUEUE_AGE_SECONDS:
            return ScaleStep.ADD_LAB_HOST
        if self.oldest_job_age > ADD_WORKER_QUEUE_AGE_SECONDS and over_an_hour_for >= ADD_WORKER_SUSTAINED_SECONDS:
            return ScaleStep.ADD_WORKER
        return None


@dataclass(frozen=True)
class SignedEvidence:
    """Evidence and the lab controller's envelope over it (verified when read)."""

    evidence: Evidence
    envelope: signing.SignedEnvelope


def lab_only_verdict_may_block(identifier: str, agreeing_lab_hosts: Iterable[str]) -> bool:
    """Whether a verdict resting on lab evidence ALONE may be served block-tier.

    False means flag-tier. Address types (domains, URLs, IPs, wallets) only ever
    flag from a lab run; a block-tier type (package, skill, file fingerprint)
    may block only when :data:`INDEPENDENT_LAB_HOSTS_TO_BLOCK` distinct lab hosts
    agree — so, until Lab 2 exists, every lab-only verdict is flag-tier."""
    block_tier_type = (threat_ids.category_for(identifier) in _BLOCK_TIER_CATEGORIES
                       or identifier.startswith(_FINGERPRINT_PREFIX))
    return block_tier_type and len(set(agreeing_lab_hosts)) >= INDEPENDENT_LAB_HOSTS_TO_BLOCK


def evidence_digest(evidence: Evidence) -> str:
    """sha256 of the canonical evidence bytes — the stored file's name."""
    return hashlib.sha256(evidence_schema.to_json(evidence).encode("utf-8")).hexdigest()


def evidence_payload(evidence: Evidence, signed_at: int) -> dict[str, str]:
    """What the lab controller signs: the job id, the image hash, the run's
    timestamps, the signing time, and the digest binding every other field."""
    return {"job_key": evidence.job_key, "image_sha256": evidence.image_sha256,
            "started_at": str(evidence.started_at), "finished_at": str(evidence.finished_at),
            "signed_at": str(signed_at), "evidence_sha256": evidence_digest(evidence)}


def verify_signed_evidence(signed: SignedEvidence, *, environment: str, lab_key: str) -> bool:
    """Whether *signed* carries one valid signature by *lab_key* (public hex) over
    exactly this evidence. Never raises."""
    envelope = signed.envelope
    signer = signing.verify(envelope, statement_type=LAB_EVIDENCE_STATEMENT, environment=environment, graph="")
    if signer is None or signer != lab_key.lower():
        return False
    expected = evidence_payload(signed.evidence, 0)
    payload = dict(envelope.payload)
    if not payload.pop("signed_at", "").isdigit():
        return False
    expected.pop("signed_at")
    return payload == expected


class LabController:
    """Submit, poll, collect, sign and store (see the module doc).

    *ctx* — the curate context (its ``sign`` is the choke point; its
    environment binds the envelope); *key* — the lab controller's own key;
    *lab_dir* — default ``<curate home>/lab``; *clock* — UTC epoch seconds."""

    def __init__(self, ctx: CurateContext, key: Ed25519PrivateKey, transport: LabTransport, extractor: Extractor,
                 *, lab_dir: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._ctx = ctx
        self._key = key
        self._transport = transport
        self._extractor = extractor
        self._clock = clock
        self._lab_dir = lab_dir or (keys.curate_home() / "lab")
        self._store = LabJobStore(self._lab_dir / "jobs.jsonl", clock=clock)
        self._lock = threading.Lock()
        self._attempts: dict[str, int] = self._load_attempts()

    @property
    def store(self) -> LabJobStore:
        return self._store

    def submit(self, identifier: str, *, level: int, image_sha256: str, lane: Lane,
               requested_by: str) -> LabJobRecord:
        """Admit a job (the store: one per key, bounded — a full store REFUSES)
        and send it to the lab at once. A known key returns its stored record."""
        record = self._store.request(identifier, level=level, image_sha256=image_sha256, lane=lane,
                                     requested_by=requested_by)
        if record.state is not LabJobState.QUEUED:
            return record
        with self._lock:
            # Re-read under the lock: a poll may have sent this job meanwhile.
            current = self._store.get(record.job.key)
            if current is None or current.state is not LabJobState.QUEUED:
                return current or record
            return self._dispatch(current)

    def poll(self) -> None:
        """One beat: send QUEUED jobs, ask after RUNNING ones, collect finished runs."""
        with self._lock:
            for record in self._store.queued():
                self._dispatch(record)
            for record in self._store.records():
                if record.state is LabJobState.RUNNING:
                    self._check(record)
            self._forget_settled_attempts()

    def evidence(self, key: str) -> Optional[SignedEvidence]:
        """The stored evidence of a DONE job with its envelope, when the envelope
        verifies against this controller's key; else None (logged)."""
        record = self._store.get(key)
        if record is None or record.evidence_sha256 is None:
            return None
        envelope_path = self._lab_dir / "evidence" / f"{record.evidence_sha256}{_ENVELOPE_SUFFIX}"
        try:
            envelope = signing.from_text(envelope_path.read_text(encoding="utf-8-sig"))
            evidence = self._store.evidence(record)
        except (OSError, ValueError) as exc:
            logger.warning("blackbox lab: evidence %s unreadable: %s", record.evidence_sha256, exc)
            return None
        signed = SignedEvidence(evidence, envelope) if envelope is not None and evidence is not None else None
        if signed is None or not verify_signed_evidence(signed, environment=self._ctx.environment,
                                                        lab_key=signing.public_key_hex(self._key)):
            logger.warning("blackbox lab: evidence %s does not verify", record.evidence_sha256)
            return None
        return signed

    def metrics(self) -> LabMetrics:
        """jobs/h, queue depth and oldest job age, from the job store."""
        now = self._clock()
        records = self._store.records()
        waiting = [r for r in records if r.state in WAITING_STATES]
        finished = [r for r in records if r.finished_at is not None and now - r.finished_at <= _HOUR]
        oldest = min((r.job.requested_at for r in waiting), default=now)
        return LabMetrics(jobs_per_hour=len(finished), queue_depth=len(waiting), oldest_job_age=now - oldest)

    # -- one job's steps (callers hold the lock) ---------------------------------

    def _dispatch(self, record: LabJobRecord) -> LabJobRecord:
        """Send *record*'s job to the lab, unless its runs are used up."""
        key = record.job.key
        if self._attempts.get(key, 0) >= MAX_ATTEMPTS:
            return self._store.could_not_tell(key)
        answer = self._transport.submit(record.job)
        if answer.outcome is LabOutcome.UNAVAILABLE:
            return record                                   # never ran: ask again next beat
        if answer.outcome is LabOutcome.REFUSED:
            return self._store.could_not_tell(key)          # the lab will not run it: a definite no
        self._count_attempt(key)
        return self._store.start(key) if record.state is LabJobState.QUEUED else record

    def _check(self, record: LabJobRecord) -> LabJobRecord:
        answer = self._transport.status(record.job.key)
        if answer.outcome is LabOutcome.UNAVAILABLE:
            return record                                   # the deadline bounds the wait
        if answer.outcome is LabOutcome.REFUSED:
            return self._dispatch(record)                   # the lab lost the job: run it again
        state = answer.body.get("state") if answer.body else None
        if state == "done":
            return self._collect(record)
        if state == "failed":
            return self._dispatch(record)
        return record

    def _collect(self, record: LabJobRecord) -> LabJobRecord:
        key = record.job.key
        answer: LabAnswer = self._transport.output(key)
        if answer.outcome is LabOutcome.UNAVAILABLE:
            return record
        if answer.outcome is LabOutcome.REFUSED or answer.body is None:
            return self._dispatch(record)
        try:
            evidence = self._extractor(record.job, answer.body)
            if evidence.job_key != key:
                raise EvidenceError("the lab answered with another job's evidence")
        except EvidenceError as exc:
            logger.warning("blackbox lab: run of %s gave unusable output: %s", key, exc)
            return self._dispatch(record)
        envelope = self._ctx.sign(EvidenceDraft(evidence_payload(evidence, int(self._clock()))), self._key)
        evidence_dir = self._lab_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        # The envelope lands first: evidence without its envelope never verifies.
        _write_atomic(evidence_dir / f"{evidence_digest(evidence)}{_ENVELOPE_SUFFIX}", envelope.to_text() + "\n")
        return self._store.complete(key, evidence)

    # -- the attempt count, kept across restarts -----------------------------------

    def _count_attempt(self, key: str) -> None:
        self._attempts[key] = self._attempts.get(key, 0) + 1
        self._save_attempts()

    def _forget_settled_attempts(self) -> None:
        open_keys = {r.job.key for r in self._store.records()
                     if r.state in (LabJobState.QUEUED, LabJobState.RUNNING)}
        if set(self._attempts) - open_keys:
            self._attempts = {key: count for key, count in self._attempts.items() if key in open_keys}
            self._save_attempts()

    def _save_attempts(self) -> None:
        self._lab_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(self._lab_dir / _ATTEMPTS_FILE, json.dumps(self._attempts, sort_keys=True))

    def _load_attempts(self) -> dict[str, int]:
        try:
            raw = json.loads((self._lab_dir / _ATTEMPTS_FILE).read_text(encoding="utf-8-sig"))
            if not isinstance(raw, dict):
                raise ValueError("not an object")
        except FileNotFoundError:
            return {}
        except ValueError:
            # Unreadable: assume every run is used up rather than grant fresh retries.
            logger.warning("blackbox lab: attempts file unreadable; open jobs get no more retries")
            return {r.job.key: MAX_ATTEMPTS for r in self._store.records()}
        return {str(key): int(count) for key, count in raw.items()
                if evidence_schema.is_job_key(key) and isinstance(count, int) and not isinstance(count, bool)}
