"""The key console's roster decisions: join requests, the next key list, renewal (trust-and-threat-lab C3, §03.2).

Everything here is a pure decision or a value, plus ONE small store
(:class:`ConsoleState`); ``routes.py`` is the HTTP over it and
``root_signer.RootSigner`` does the signing. The next key list is always
built by the K2 validator (``KeyManifest`` construction), so a list outside
the threshold table, a bad operator or a duplicate key can never be signed.

* A JOIN REQUEST is a curator public key + its operator + the curator's
  self-test against the fixed fixture set (:data:`SELF_TEST_FIXTURES`: 10
  known threats confirmed, 10 known-clean rejected, 2 could-not-tell left
  unproven). Only a passing self-test may be approved.
* :func:`with_curator` / :func:`without_curator` / :func:`renewed` build the
  next unsigned list from the effective one; :func:`diff` is what the console
  shows before Amos signs. A removal is a NARROWING list (K2 ``narrows``: one
  key per list) and keeps the effective list's ``issued_day`` — readers act on
  a narrowing list at once, so a fresh day would extend its validity without
  the waiting period.
* One narrowing list per :data:`NARROWING_INTERVAL_SECONDS` per root epoch
  (:meth:`ConsoleState.narrowing_refusal`).
* :func:`renewal_status` — reminders at days 40/50/55 of MANIFEST_VALID_DAYS,
  an alarm once fewer than :data:`ALARM_DAYS_LEFT` days are left.

Usage::

    state = ConsoleState()                                     # <curate home>/console_state.json
    state.submit(JoinRequest.new(key, "Umoja Ark", SelfTestReport.from_mapping(body), now))
    proposed = with_curator(effective, key, "Umoja Ark", version=state.next_version(effective), today=today)
    diff(effective, proposed)                                  # shown before signing
    renewal_status(effective, today)                           # RenewalStatus(stage="reminder", milestone=40, ...)
"""

from __future__ import annotations

import dataclasses
import json
import re
import threading
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional

from ...kernel import threat_ids
from ...kernel.bounded_files import atomic_write
from ...kernel.signing import key_manifest
from ...kernel.signing import KeyManifest
from .. import keys

STATE_FILE = "console_state.json"
#: The fixed self-test fixture set a joining curator is judged on (§03.2, F-020).
SELF_TEST_FIXTURES: Mapping[str, int] = {"threatsConfirmed": 10, "cleanRejected": 10, "unprovenLeft": 2}
#: K2: one narrowing list per this many seconds per root epoch.
NARROWING_INTERVAL_SECONDS = 24 * 60 * 60
REMINDER_DAYS = (40, 50, 55)
ALARM_DAYS_LEFT = 5
MAX_PENDING_JOINS = 32
MAX_DECIDED_JOINS = 64
MAX_SIGNED_LISTS = 50
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")


def _waiting_seconds() -> int:
    """How long a non-narrowing list waits before readers act on it (0 = no wait);
    until then the console builds on nothing newer. Read at call time."""
    return key_manifest.MANIFEST_TIME_LOCK_DAYS * 24 * 60 * 60


class RosterError(ValueError):
    """A roster change the console refuses; the message says why (safe to show)."""


@dataclass(frozen=True)
class SelfTestReport:
    """A joining curator's self-test: per fixture group, how many it got right, on UTC *day*."""

    day: str
    threats_confirmed: int
    clean_rejected: int
    unproven_left: int

    @property
    def passed(self) -> bool:
        return self.as_dict() == {"day": self.day, **SELF_TEST_FIXTURES}

    def as_dict(self) -> dict[str, object]:
        return {"day": self.day, "threatsConfirmed": self.threats_confirmed, "cleanRejected": self.clean_rejected,
                "unprovenLeft": self.unproven_left}

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> SelfTestReport:
        """Validated; :class:`RosterError` on a bad day or a count outside its fixture group."""
        day = str(data.get("day") or "")
        if not _DAY.fullmatch(day):
            raise RosterError("the self-test day must be a UTC day (YYYY-MM-DD)")
        counts = {}
        for field, most in SELF_TEST_FIXTURES.items():
            value = data.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= most:
                raise RosterError(f"self-test {field} must be a whole number from 0 to {most}")
            counts[field] = value
        return cls(day, counts["threatsConfirmed"], counts["cleanRejected"], counts["unprovenLeft"])


class JoinState(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"


@dataclass(frozen=True)
class JoinRequest:
    """One curator asking to join: ``curator_key`` (Ed25519 public hex, the id),
    ``operator`` (the organisation running it), its ``self_test``, when it was
    received, and Amos's decision."""

    curator_key: str
    operator: str
    self_test: SelfTestReport
    received_at: float
    state: JoinState = JoinState.PENDING

    @classmethod
    def new(cls, curator_key: str, operator: str, self_test: SelfTestReport, now: float) -> JoinRequest:
        """Bounded at the boundary (:class:`RosterError`); the full K2 operator
        rules run when the list naming it is built (:func:`with_curator`)."""
        if not threat_ids.is_hex64(curator_key):
            raise RosterError("the curator key must be an Ed25519 public key (64 lower-case hex)")
        if not operator.strip() or len(operator) > key_manifest.MAX_OPERATOR_LENGTH:
            raise RosterError(f"the operator must be a name of 1-{key_manifest.MAX_OPERATOR_LENGTH} characters")
        return cls(curator_key, operator, self_test, now)

    def as_dict(self) -> dict[str, object]:
        return {"curatorKey": self.curator_key, "operator": self.operator, "selfTest": self.self_test.as_dict(),
                "selfTestPassed": self.self_test.passed, "receivedAt": self.received_at, "state": self.state.value}

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> JoinRequest:
        return cls(str(data["curatorKey"]), str(data["operator"]),
                   SelfTestReport.from_mapping(data["selfTest"]),   # type: ignore[arg-type]
                   float(data["receivedAt"]), JoinState(data["state"]))   # type: ignore[arg-type]


@dataclass(frozen=True)
class SignedList:
    """A key list root A signed here: its order, whether it narrowed, and when."""

    root_epoch: int
    version: int
    narrowing: bool
    at: float


class ConsoleState:
    """The console's own memory: join requests and the lists it signed.

    ``<curate home>/console_state.json`` (0600, atomic replace), one lock,
    bounded (:data:`MAX_PENDING_JOINS` pending — more is refused; the oldest
    decided requests and signed-list rows are dropped). A damaged file reads
    as no joins, and every signing check refuses (fail closed).
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / STATE_FILE)
        self._lock = threading.Lock()

    def joins(self) -> list[JoinRequest]:
        with self._lock:
            return list(self._read()[0].values())

    def join(self, curator_key: str) -> Optional[JoinRequest]:
        with self._lock:
            return self._read()[0].get(curator_key)

    def submit(self, request: JoinRequest) -> None:
        """Store a new PENDING request; refused when that key already waits or the queue is full."""
        with self._lock:
            joins, lists = self._read()
            current = joins.get(request.curator_key)
            if current is not None and current.state is JoinState.PENDING:
                raise RosterError("a join request for this key is already waiting")
            if sum(1 for j in joins.values() if j.state is JoinState.PENDING) >= MAX_PENDING_JOINS:
                raise RosterError(f"{MAX_PENDING_JOINS} join requests are already waiting; decide some first")
            joins[request.curator_key] = request
            self._write(joins, lists)

    def decide(self, curator_key: str, state: JoinState) -> JoinRequest:
        """Mark a PENDING request approved or declined."""
        with self._lock:
            joins, lists = self._read()
            current = joins.get(curator_key)
            if current is None or current.state is not JoinState.PENDING:
                raise RosterError("no waiting join request for this key")
            joins[curator_key] = dataclasses.replace(current, state=state)
            self._write(joins, lists)
            return joins[curator_key]

    def record_list(self, signed: SignedList) -> None:
        with self._lock:
            joins, lists = self._read()
            self._write(joins, None if lists is None else lists + [signed])

    def next_version(self, effective: KeyManifest) -> int:
        """One above both the effective list and every list signed here for its epoch
        (two different lists at one order would freeze every reader)."""
        lists = self._signed_lists()
        return max([effective.version] + [s.version for s in lists if s.root_epoch == effective.root_epoch]) + 1

    def narrowing_refusal(self, root_epoch: int, now: float) -> str:
        """Why a narrowing list may not be signed now ("" = it may)."""
        lists = self._signed_lists()
        recent = [s for s in lists if s.root_epoch == root_epoch and s.narrowing and now - s.at < NARROWING_INTERVAL_SECONDS]
        return "one narrowing list per 24 h per root epoch: the last one was signed less than 24 h ago" if recent else ""

    def waiting_refusal(self, effective: KeyManifest, now: float) -> str:
        """Why a widening or renewing list may not be built on *effective* now ("" = it may):
        a newer list signed here is still inside its waiting period, and building
        on the older list would silently drop its change."""
        lists = self._signed_lists()
        waiting = [s for s in lists if s.root_epoch == effective.root_epoch and s.version > effective.version
                   and not s.narrowing and now - s.at < _waiting_seconds()]
        return (f"version {max(s.version for s in waiting)} signed here is still in its waiting period; "
                "approve again after readers act on it") if waiting else ""

    def _signed_lists(self) -> list[SignedList]:
        """The lists signed here; :class:`RosterError` when the state is unreadable — a
        version or a 24 h check made from a damaged record could repeat an order and
        freeze every reader, so the console signs nothing until it is repaired."""
        with self._lock:
            lists = self._read()[1]
        if lists is None:
            raise RosterError(f"the console state {self._path.name} is unreadable; nothing is signed until it is repaired")
        return lists

    def _read(self) -> tuple[dict[str, JoinRequest], Optional[list[SignedList]]]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            return {}, []
        except (OSError, ValueError):
            return {}, None
        try:
            joins = {j.curator_key: j for j in (JoinRequest.from_dict(row) for row in data.get("joins", []))}
            lists = [SignedList(int(r["root_epoch"]), int(r["version"]), bool(r["narrowing"]), float(r["at"]))
                     for r in data.get("signedLists", [])]
        except (KeyError, TypeError, ValueError):
            return {}, None
        return joins, lists

    def _write(self, joins: dict[str, JoinRequest], lists: Optional[list[SignedList]]) -> None:
        if lists is None:   # never overwrite a damaged record: it holds the 24 h and version history
            raise RosterError(f"the console state {self._path.name} is unreadable; repair it before any change")
        pending = [j for j in joins.values() if j.state is JoinState.PENDING]
        decided = sorted((j for j in joins.values() if j.state is not JoinState.PENDING), key=lambda j: j.received_at)
        rows = {"joins": [j.as_dict() for j in pending + decided[-MAX_DECIDED_JOINS:]],
                "signedLists": [dataclasses.asdict(s) for s in lists[-MAX_SIGNED_LISTS:]]}
        atomic_write(self._path, json.dumps(rows, sort_keys=True), mode=0o600, durable=True)


# -- the next list ---------------------------------------------------------------


def _next(effective: KeyManifest, curators: Mapping[str, str], **changes: object) -> KeyManifest:
    """*effective* with a new roster and *changes*, through the K2 validator."""
    try:
        return dataclasses.replace(effective, **key_manifest.roster(curators), **changes)   # type: ignore[arg-type]
    except key_manifest.KeyManifestError as exc:
        raise RosterError(f"the console refuses this list: {exc}") from None


def _curators(manifest: KeyManifest) -> dict[str, str]:
    return dict(zip(manifest.curator_keys, manifest.curator_operators))


def with_curator(effective: KeyManifest, curator_key: str, operator: str, *, version: int, today: str,
                 threshold: Optional[int] = None) -> KeyManifest:
    """The list adding one curator (dated *today*, so it also renews). *threshold* — optional
    new threshold; the table refuses one outside it."""
    if curator_key in effective.curator_keys:
        raise RosterError("this key is already on the effective list")
    return _next(effective, {**_curators(effective), curator_key: operator}, version=version, issued_day=today,
                 threshold=effective.threshold if threshold is None else threshold)


def without_curator(effective: KeyManifest, curator_key: str, *, version: int) -> KeyManifest:
    """The NARROWING list removing one curator at once (see the module doc)."""
    if curator_key not in effective.curator_keys:
        raise RosterError("this key is not on the effective list")
    if curator_key == effective.break_glass_key:
        raise RosterError("the break-glass key cannot be removed by a narrowing list")
    curators = _curators(effective)
    del curators[curator_key]
    proposed = _next(effective, curators, version=version)
    if not proposed.narrows(effective):
        raise RosterError("the list would not only narrow the effective one")
    return proposed


def renewed(effective: KeyManifest, *, version: int, today: str) -> KeyManifest:
    """The same list, dated *today* (a fresh MANIFEST_VALID_DAYS)."""
    return _next(effective, _curators(effective), version=version, issued_day=today)


def diff(effective: KeyManifest, proposed: KeyManifest) -> dict[str, object]:
    """What signing *proposed* changes against the effective list (shown before signing)."""
    before, after = _curators(effective), _curators(proposed)
    return {
        "added": [{"curatorKey": k, "operator": after[k]} for k in sorted(set(after) - set(before))],
        "removed": [{"curatorKey": k, "operator": before[k]} for k in sorted(set(before) - set(after))],
        "threshold": [effective.threshold, proposed.threshold],
        "version": [effective.version, proposed.version],
        "issuedDay": [effective.issued_day, proposed.issued_day],
        "rootEpoch": proposed.root_epoch,
        "narrowing": proposed.narrows(effective),
    }


# -- renewal -----------------------------------------------------------------------


@dataclass(frozen=True)
class RenewalStatus:
    """Where the effective list stands on its MANIFEST_VALID_DAYS clock.

    ``stage`` — "ok" | "reminder" | "alarm" | "undated"; ``milestone`` — the
    last reminder day reached (0 = none); ``days_left`` — until it expires
    (negative once expired); ``expires`` — the expiry day ("" when undated).
    """

    stage: str
    milestone: int
    days_left: int
    expires: str

    def as_dict(self) -> dict[str, object]:
        return {"stage": self.stage, "milestone": self.milestone, "daysLeft": self.days_left, "expires": self.expires}


def renewal_status(manifest: KeyManifest, today: str) -> RenewalStatus:
    """Reminders from day 40, 50 and 55 on (each stays shown until the next, so a
    console opened a day late still sees it); an ALARM once fewer than
    :data:`ALARM_DAYS_LEFT` days are left, or after expiry — an expired list
    silently stops all curation, so the alarm is loud. An unreadable day is an alarm."""
    if not manifest.issued_day:
        return RenewalStatus("undated", 0, 0, "")
    try:
        age = (date.fromisoformat(today) - date.fromisoformat(manifest.issued_day)).days
    except ValueError:
        return RenewalStatus("alarm", 0, 0, "")
    expires = (date.fromisoformat(manifest.issued_day) + timedelta(days=key_manifest.MANIFEST_VALID_DAYS)).isoformat()
    days_left = key_manifest.MANIFEST_VALID_DAYS - age
    milestone = max((day for day in REMINDER_DAYS if age >= day), default=0)
    if days_left < ALARM_DAYS_LEFT:
        return RenewalStatus("alarm", milestone, days_left, expires)
    return RenewalStatus("reminder" if milestone else "ok", milestone, days_left, expires)


__all__ = [
    "ALARM_DAYS_LEFT",
    "NARROWING_INTERVAL_SECONDS",
    "REMINDER_DAYS",
    "SELF_TEST_FIXTURES",
    "ConsoleState",
    "JoinRequest",
    "JoinState",
    "RenewalStatus",
    "RosterError",
    "SelfTestReport",
    "SignedList",
    "diff",
    "renewal_status",
    "renewed",
    "with_curator",
    "without_curator",
]
