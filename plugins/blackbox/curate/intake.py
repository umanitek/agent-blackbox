"""Intake — what reaches the curator: new community threats (Refine R6), alarms (trust-and-threat-lab W3) and public disputes (§03.3).

Plan §09 INTAKE: ``blackbox curate watch`` polls the delta view and tells the
curator about NEW threats through ONE webhook — the direction the shipped
graph never proved (a report on bench B reaching the curator's queue).

Pattern: Observer — :class:`IntakeWatcher` remembers what it already announced
(``$BLACKBOX_HOME/curate/intake_seen.json``) and notifies a sink;
:class:`AlarmWatcher` does the same for alarms (``<curate home>/alarms_seen.json``):
the curator alarms, the manifest watcher's items (``watch.manifest_items``, W1),
the ledger checks of ``curate.watch`` (W2) and the watcher's own daily
dead-man beat; it also posts the F-035 metrics record (``curate.console.PipelineMetrics``,
C4's one record) at most hourly. The
sinks and each node's OWN sink credential (``watch.node_sink``)
live in ``curate.watch.delivery``.

DISPUTES (trust-and-threat-lab §03.3, SVC3): a listed party (package owner,
domain owner…) files a dispute on the public page; :class:`DisputeIntake` is
the endpoint's server side. It validates EVERY field against a closed
vocabulary (:func:`validate_dispute_submission`), signs the queue item through
the signing choke point (``CurateContext.sign(DisputeDraft)``) and stores it
in :class:`DisputeStore`, where it waits in queue lane ``dispute``. Data kept
to the minimum (FMN-V10-PRIVACY): the signed item holds the threat identifier,
the party kind and a reason code — never a person's details; the reply
address the form needs lives in a separate 0600 file and is erased when the
dispute closes. The endpoint is rate-limited as a whole (no per-sender
memory, so no sender is tracked).

Usage::

    watcher, alarms, sink = IntakeWatcher(), AlarmWatcher(), watch.node_sink()
    announced = watcher.poll(delta_view, sink)
    alarms.poll(curator_items + watch.manifest_items(ctx.manifest, now) + watch_items, sink, now=now)
    alarms.post_metrics(lambda: console.collect_metrics(console.MetricsSources(), lambda: ctx, now), sink, now)

    answer = DisputeIntake(ctx).submit(request_json)   # IntakeAnswer(status=202, body={"dispute_id", "deadline"})
    DisputeStore().open_identifiers()                  # for queue.delta_view(..., publicly_disputed=...)
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..kernel import display_safety, signing, threat_ids
from ..kernel.health import HealthItem
from . import keys
from .context import DISPUTE_INTAKE_STATEMENT, CurateContext, DisputeDraft
from .queue import DeltaView, QueueItem
from .service.disputes import DisputeRecord, DisputeStore
from .sources import TokenBucket
from .watch import IntakeEvent, IntakeSink, MetricsRecord, dead_man_beat
from ..kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

_SEEN_FILE = "intake_seen.json"
#: Most identifiers remembered (the oldest announced are forgotten first).
_MAX_SEEN = 50_000
#: The metrics record goes to the node's monitor at most this often (seconds).
METRICS_INTERVAL_S = 3600.0
#: Seen-file marker: the dead-man beat of this UTC day was delivered.
_BEAT_MARK = "dead-man beat delivered {day}"


class AlarmWatcher:
    """Delivers each alarm ONCE per message to the sink (R10b, W3), plus the daily
    dead-man beat and the hourly metrics record."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / "alarms_seen.json")
        self._lock = threading.Lock()
        self._metrics_at: Optional[float] = None

    def poll(self, items: Iterable[Any], sink: IntakeSink, *, now: Optional[float] = None) -> list[str]:
        """Notify *sink* of every alarm message not delivered before; returns them.
        With *now*, also this UTC day's dead-man beat (once a day; its absence is the alarm)."""
        items = list(items)
        with self._lock:
            seen = _load_seen(self._path)
            fresh = [item for item in items if item.message not in seen]
            delivered = [item for item in fresh if sink.notify_alarm(item) is not False]
            seen.update(dict.fromkeys(item.message for item in delivered))   # an undelivered alarm is tried again next round
            beat = self._due_beat(seen, items, now)
            if beat is not None and sink.notify_alarm(beat) is not False:
                seen[_BEAT_MARK.format(day=time.strftime("%Y-%m-%d", time.gmtime(now)))] = None
                delivered.append(beat)
            _save_seen(self._path, seen)
        return [item.message for item in delivered]

    def post_metrics(self, record_of: Callable[[], MetricsRecord], sink: IntakeSink, now: float) -> bool:
        """Post the record *record_of* builds to the node's monitor unless one went out in the
        last hour; True when posted. The record is built only when due (it reads every store)."""
        with self._lock:
            if self._metrics_at is not None and now - self._metrics_at < METRICS_INTERVAL_S:
                return False
            if sink.notify_metrics(record_of()) is False:
                return False
            self._metrics_at = now
            return True

    @staticmethod
    def _due_beat(seen: dict[str, None], items: list[Any], now: Optional[float]) -> Optional[HealthItem]:
        if now is None:
            return None
        today = time.strftime("%Y-%m-%d", time.gmtime(now))
        beat = dead_man_beat(now, today if _BEAT_MARK.format(day=today) in seen else "", items)
        return beat.as_health_item() if beat is not None else None


def _load_seen(path: Path) -> dict[str, None]:
    """What was already announced, oldest first (a dict keeps the order things were added)."""
    try:
        return dict.fromkeys(str(x) for x in json.loads(path.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, TypeError):
        return {}


def _save_seen(path: Path, seen: dict[str, None]) -> None:
    kept = list(seen)[-_MAX_SEEN:]   # past the cap the OLDEST are forgotten (it kept the alphabetically last)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, json.dumps(kept))


class IntakeWatcher:
    """Announces each NEW queue item once. One lock; atomic, bounded memory."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _SEEN_FILE)
        self._lock = threading.Lock()

    def poll(self, view: DeltaView, sink: IntakeSink) -> list[str]:
        """Notify *sink* of every item not announced before; returns their identifiers."""
        with self._lock:
            seen = _load_seen(self._path)
            fresh = [item for item in view.new if item.identifier not in seen]
            delivered = [item for item in fresh if sink.notify(_event(item)) is not False]
            seen.update(dict.fromkeys(item.identifier for item in delivered))   # KI-261: announced means DELIVERED
            _save_seen(self._path, seen)
        return [item.identifier for item in delivered]


def _event(item: QueueItem) -> IntakeEvent:
    return IntakeEvent(identifier=item.identifier, stage=item.stage, enforcement=item.enforcement,
                       reporters=item.reporters, lane=item.lane.value)


# -- disputes from the public page (trust-and-threat-lab §03.3, SVC3) -----------

#: Why a listed party disputes: the listing was never right, or the thing was cleaned up.
#: The same words as a node's own false-positive reasons, so readers share one vocabulary.
PUBLIC_DISPUTE_REASONS = ("wrong", "fixed")
#: Who is filing — the kind of party, never who they are.
DISPUTE_PARTIES = ("package-owner", "skill-author", "domain-owner", "address-owner")
#: The form's fields, all required; any other field is refused.
DISPUTE_FIELDS: frozenset[str] = frozenset({"identifier", "party", "reason", "reply_to"})
MAX_REPLY_TO_CHARS = 254
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}")
#: Open disputes held at once; past this the endpoint answers 503 (a flood cannot fill the disk).
MAX_OPEN_DISPUTES = 1000
#: Submissions the endpoint accepts per hour, across all senders.
SUBMISSIONS_PER_HOUR = 60
#: A listed threat identifier is one short token (the report schema's own bound).
MAX_IDENTIFIER_CHARS = 512


class DisputeRejected(ValueError):
    """A submission that does not fit the form; the message is safe to show the sender."""


@dataclass(frozen=True)
class DisputeSubmission:
    """One validated dispute: the canonical ``identifier`` disputed, the ``party``
    kind (:data:`DISPUTE_PARTIES`), the ``reason`` code (:data:`PUBLIC_DISPUTE_REASONS`)
    and the ``reply_to`` e-mail address — the only personal datum, kept apart and
    erased when the dispute closes."""

    identifier: str
    party: str
    reason: str
    reply_to: str


def _field(body: Mapping[str, Any], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DisputeRejected(f"{name} is required and must be text")
    return value.strip()


def validate_dispute_submission(body: Any) -> DisputeSubmission:
    """The validated submission, or :class:`DisputeRejected`. Every field is
    checked here, on the server — whatever the page checked proves nothing."""
    if not isinstance(body, Mapping):
        raise DisputeRejected("the dispute must be a JSON object")
    unknown = set(body) - DISPUTE_FIELDS
    if unknown:
        raise DisputeRejected(f"fields not allowed: {', '.join(sorted(str(name) for name in unknown))}")
    identifier = _field(body, "identifier")
    if (len(identifier) > MAX_IDENTIFIER_CHARS or any(ch.isspace() for ch in identifier)
            or display_safety.strip_controls(identifier) != identifier):
        raise DisputeRejected("the identifier must be a short single token without control or format characters")
    if threat_ids.category_for(identifier) == "other":
        raise DisputeRejected("the identifier must be a threat identifier as listed (dep:…, skill:…, ioc:…)")
    party, reason = _field(body, "party"), _field(body, "reason")
    if party not in DISPUTE_PARTIES:
        raise DisputeRejected(f"party must be one of: {', '.join(DISPUTE_PARTIES)}")
    if reason not in PUBLIC_DISPUTE_REASONS:
        raise DisputeRejected(f"reason must be one of: {', '.join(PUBLIC_DISPUTE_REASONS)}")
    reply_to = _field(body, "reply_to")
    if (len(reply_to) > MAX_REPLY_TO_CHARS or display_safety.strip_controls(reply_to) != reply_to
            or not _EMAIL.fullmatch(reply_to)):
        raise DisputeRejected("reply_to must be one e-mail address")
    return DisputeSubmission(identifier=identifier, party=party, reason=reason, reply_to=reply_to)


@dataclass(frozen=True)
class IntakeAnswer:
    """What the endpoint answers: an HTTP ``status`` and a flat JSON ``body``
    (``error`` on refusal — never a stack trace)."""

    status: int
    body: dict[str, str]


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds")


class DisputeIntake:
    """The dispute endpoint's server side (Facade over validation, the signing
    choke point and the store). ``submit`` never raises: 202 accepted (or
    already open for that identifier), 400 invalid, 429 over the hourly
    limit, 503 the queue is full or the item could not be signed."""

    #: "Already open?" → sign → store is ONE step (the console's convention for its key
    #: lists): senders of one identifier at the same instant must open one dispute, or
    #: each keeps a reply address and the lane holds the listing N times (FIX-0091).
    _admitting = threading.Lock()

    def __init__(self, ctx: CurateContext, *, key: Optional[Callable[[], Ed25519PrivateKey]] = None,
                 store: Optional[DisputeStore] = None, bucket: Optional[TokenBucket] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._ctx, self._clock = ctx, clock
        self._key = key or keys.curator_key_store().load_or_create
        self._store = store or DisputeStore()
        self._bucket = bucket or TokenBucket(SUBMISSIONS_PER_HOUR, 3600.0)

    def submit(self, body: Any) -> IntakeAnswer:
        if not self._bucket.take():
            return IntakeAnswer(429, {"error": "too many disputes right now; please try again in an hour"})
        try:
            submission = validate_dispute_submission(body)
        except DisputeRejected as exc:
            return IntakeAnswer(400, {"error": str(exc)})
        with self._admitting:
            return self._admit(submission)

    def _admit(self, submission: DisputeSubmission) -> IntakeAnswer:
        open_now = self._store.open_records()
        already = next((r for r in open_now if r.identifier == submission.identifier), None)
        if already is not None:   # one open dispute per listing; a second sender's address is not kept
            return IntakeAnswer(202, {"dispute_id": already.dispute_id, "deadline": _iso(already.deadline),
                                      "state": "already open"})
        if len(open_now) >= MAX_OPEN_DISPUTES:
            return IntakeAnswer(503, {"error": "the dispute queue is full; please try again later"})
        try:
            record = self._signed(submission)
        except (ValueError, OSError) as exc:
            logger.warning("blackbox curate: a dispute could not be signed: %s", exc)
            return IntakeAnswer(503, {"error": "the dispute could not be recorded; please try again later"})
        self._store.add(record, submission.reply_to)
        return IntakeAnswer(202, {"dispute_id": record.dispute_id, "deadline": _iso(record.deadline), "state": "open"})

    def _signed(self, submission: DisputeSubmission) -> DisputeRecord:
        dispute_id, filed_at = secrets.token_hex(8), float(int(self._clock()))
        payload = {"dispute_id": dispute_id, "identifier": submission.identifier, "party": submission.party,
                   "reason": submission.reason, "filed_at": str(int(filed_at))}
        envelope = self._ctx.sign(DisputeDraft(payload), self._key())
        return DisputeRecord(dispute_id=dispute_id, identifier=submission.identifier, party=submission.party,
                             reason=submission.reason, filed_at=filed_at, envelope=envelope.to_text())


def verified_dispute_item(text: str, *, environment: str, curator_keys: Iterable[str]) -> Optional[Mapping[str, str]]:
    """The payload of a signed dispute item when ONE of *curator_keys* signed
    it for *environment*; None for anything else (how the other curator checks
    an item it was sent before it re-runs the look-ups)."""
    envelope = signing.from_text(text)
    signer = signing.verify(envelope, statement_type=DISPUTE_INTAKE_STATEMENT, environment=environment, graph="")
    if envelope is None or signer is None or signer not in set(curator_keys):
        return None
    return envelope.payload
