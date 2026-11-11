"""The manifest watcher's health items (trust-and-threat-lab W1, F-003).

Three checks about the curators' trust layer, each a pure function of plain
facts the caller gathers:

* **a new root-signed list** — SECURITY when a root-signed curator key list
  (a key manifest) newer than the last one this node recorded is on the graph.
  The node records the newest order it has seen in :class:`SeenOrderRecord`;
  the item stays up until that record is raised (:meth:`SeenOrderRecord.acknowledge`),
  so a list nobody expected cannot pass unnoticed between two polls;
* **heartbeat gaps** — a curator key that missed :data:`MISSED_BEATS_WARNING`
  beats → ACTION (a warning); silent longer than :data:`SILENCE_ALARM_S` →
  SECURITY (an alarm). Readers' own 48 h INFO rule (``HEARTBEAT_SILENCE_DAYS``
  in the package) is unchanged — this is the curator nodes' faster watch;
* **renewal reminders** — a key manifest lives ``MANIFEST_VALID_DAYS``; ACTION
  reminders at days :data:`REMINDER_DAYS`, and SECURITY inside the last
  :data:`EXPIRY_ALARM_DAYS` days (and after expiry), because an expired list
  stops all curation.

Facts in, alarms out (the same shape as :mod:`.community_authority`):
:func:`alarms` returns ``(class, message, what to do)`` and
``kernel.health.operator_health`` wraps them, so ``blackbox status``, the
dashboard and the curate beat all show the same items. Every message stays
the same while its condition holds (no live counters), because the alarm
sink delivers each distinct message once. Alarm text names statement kinds,
key fingerprints, counts, orders and times — never a report's identifier or
text (proposal §00 scope).

Usage::

    record = SeenOrderRecord(curate_home / SEEN_ORDER_FILE)
    inputs = watch_inputs(record, seen_orders, heartbeats={key: last_beat_time}, beat_interval_s=300,
                          manifest_order=manifest.order, issued_day=manifest.issued_day, now=time.time())
    items = health.operator_health(health.HealthInputs(..., manifest_watch=inputs))
    record.acknowledge(order)   # the key console, after signing that list itself
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, UTC
from pathlib import Path
from typing import Iterable, Mapping, Optional

from ..signing.key_manifest import KEY_MANIFEST_STATEMENT, MANIFEST_VALID_DAYS
from ..yaml_files import atomic_write
from .community_authority import Alarm

#: A key manifest's order: (root epoch, version).
Order = tuple[int, int]

#: The file under the caller's state folder (the curate home on curator nodes) holding the recorded order.
SEEN_ORDER_FILE = "manifest_seen_order.json"
#: This many missed curator beats → a warning (ACTION).
MISSED_BEATS_WARNING = 3
#: A curator key silent longer than this many seconds (2 h) → an alarm (SECURITY).
SILENCE_ALARM_S = 2 * 60 * 60
#: Days after the manifest's issue day on which the renewal reminder steps up.
REMINDER_DAYS = (40, 50, 55)
#: Inside this many days of MANIFEST_VALID_DAYS the reminder becomes an alarm.
EXPIRY_ALARM_DAYS = 5
#: Alarm text names a key by this many leading hex characters, never more.
KEY_FINGERPRINT_CHARS = 16


def key_fingerprint(key: str) -> str:
    """The short form of a public key that alarm text may name."""
    return key[:KEY_FINGERPRINT_CHARS]


def _order_text(order: Order) -> str:
    return f"epoch {order[0]}, version {order[1]}"


def _time_text(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class ManifestWatchInputs:
    """What the watcher looks at (all optional — the defaults raise nothing).

    ``seen_orders`` — the order of every root-signed key manifest on the graph
    now (pending and freeze-only ones included: a list inside its time-lock is
    exactly what must be noticed); ``recorded_order`` — the newest order this
    node recorded (None = nothing recorded); ``record_unreadable`` — the
    record exists but could not be read (could not tell → SECURITY, never
    "nothing new"); ``heartbeats`` — curator key (hex) → time of its newest
    heartbeat (epoch seconds), for the keys of the list in force;
    ``beat_interval_s`` — how often a curator beats (≤ 0 = unknown, the
    missed-beat warning is skipped, the 2 h alarm still applies);
    ``manifest_order`` / ``issued_day`` — the list in force and the UTC day its
    root signed it ("" = undated, no reminders); ``now`` — epoch seconds.
    """

    seen_orders: tuple[Order, ...] = ()
    recorded_order: Optional[Order] = None
    record_unreadable: bool = False
    heartbeats: Mapping[str, float] = field(default_factory=dict)
    beat_interval_s: float = 0.0
    manifest_order: Optional[Order] = None
    issued_day: str = ""
    now: float = 0.0


class SeenOrderRecord:
    """The newest root-signed list order this node has recorded — one small JSON file.

    :meth:`read` returns the order, None when nothing is recorded yet, and
    raises :class:`SeenOrderRecordError` when the file exists but is unusable
    (a damaged record must alarm, never silently reset). :meth:`acknowledge`
    only ever raises the order: a lower one is ignored, so a stale writer can
    at worst re-show an alarm, never hide one.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def read(self) -> Optional[Order]:
        try:
            text = self._path.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SeenOrderRecordError(f"cannot read {self._path.name}") from exc
        try:
            data = json.loads(text)
            order = (int(data["root_epoch"]), int(data["version"]))
        except (ValueError, TypeError, KeyError) as exc:
            raise SeenOrderRecordError(f"{self._path.name} is damaged") from exc
        return order

    def acknowledge(self, order: Order) -> None:
        """Record *order* as seen, unless a newer one is already recorded."""
        try:
            current = self.read()
        except SeenOrderRecordError:
            current = None   # a damaged record is replaced by the acknowledged order
        if current is not None and current >= tuple(order):
            return
        atomic_write(self._path, json.dumps({"root_epoch": int(order[0]), "version": int(order[1])}))


class SeenOrderRecordError(ValueError):
    """The recorded order exists but cannot be read."""


def watch_inputs(record: SeenOrderRecord, seen_orders: Iterable[Order], *, heartbeats: Mapping[str, float],
                 beat_interval_s: float, manifest_order: Optional[Order], issued_day: str,
                 now: float) -> ManifestWatchInputs:
    """Build :class:`ManifestWatchInputs`, reading the record. On a node that has
    recorded nothing yet, the newest list seen now is recorded first (a fresh
    install trusts the lists already on the graph, as its pinned roots do);
    from then on only a list newer than the record raises the SECURITY item."""
    orders = tuple(sorted({(int(epoch), int(version)) for epoch, version in seen_orders}))
    try:
        recorded, unreadable = record.read(), False
    except SeenOrderRecordError:
        recorded, unreadable = None, True
    if recorded is None and not unreadable and orders:
        record.acknowledge(orders[-1])
        recorded = orders[-1]
    return ManifestWatchInputs(seen_orders=orders, recorded_order=recorded, record_unreadable=unreadable,
                               heartbeats=dict(heartbeats), beat_interval_s=beat_interval_s,
                               manifest_order=manifest_order, issued_day=issued_day, now=now)


def alarms(inputs: ManifestWatchInputs) -> list[Alarm]:
    """The watcher's alarms for *inputs*, as (class, message, what to do)."""
    return _new_lists(inputs) + _heartbeat_gaps(inputs) + _renewal(inputs)


def _new_lists(inputs: ManifestWatchInputs) -> list[Alarm]:
    if inputs.record_unreadable:
        return [("security", "this node's record of root-signed curator key lists is unreadable",
                 "check every root-signed list on the graph was signed in the key console, then acknowledge the newest")]
    if inputs.recorded_order is None:
        return []
    newer = [order for order in inputs.seen_orders if order > inputs.recorded_order]
    if not newer:
        return []
    return [("security", f"{len(newer)} root-signed {KEY_MANIFEST_STATEMENT} list(s) newer than the last one this node "
                         f"recorded ({_order_text(inputs.recorded_order)}); newest {_order_text(max(newer))}",
             "confirm the key console signed it (its signing log); if it did not, freeze it with the other root and replace the key now")]


def _heartbeat_gaps(inputs: ManifestWatchInputs) -> list[Alarm]:
    out: list[Alarm] = []
    for key, last in sorted(inputs.heartbeats.items()):
        silence = inputs.now - last
        since = _time_text(last)
        if silence > SILENCE_ALARM_S:
            out.append(("security", f"curator key {key_fingerprint(key)} silent for more than 2 h (last heartbeat {since})",
                        "check that curator's node and service now; a long silence on both curators halts curation"))
        elif inputs.beat_interval_s > 0 and silence >= MISSED_BEATS_WARNING * inputs.beat_interval_s:
            out.append(("action", f"curator key {key_fingerprint(key)} missed {MISSED_BEATS_WARNING} or more beats "
                                  f"(last heartbeat {since})",
                        "check that curator's service (`blackbox curate run`); an alarm follows after 2 h of silence"))
    return out


def _renewal(inputs: ManifestWatchInputs) -> list[Alarm]:
    if not inputs.issued_day or inputs.manifest_order is None:
        return []
    today = datetime.fromtimestamp(inputs.now, UTC).date()
    try:
        issued = date.fromisoformat(inputs.issued_day)
    except ValueError:
        return []   # an undatable list is already STALE by the manifest clock (kernel.health._trust)
    age = (today - issued).days
    expires = (issued + timedelta(days=MANIFEST_VALID_DAYS)).isoformat()
    listed = f"the curator key list ({_order_text(inputs.manifest_order)})"
    if age > MANIFEST_VALID_DAYS - EXPIRY_ALARM_DAYS:
        verb = "EXPIRED on" if age > MANIFEST_VALID_DAYS else "expires on"
        return [("security", f"{listed} {verb} {expires}",
                 "renew it in the key console now — an expired list stops all curation")]
    reached = [day for day in REMINDER_DAYS if age >= day]
    if not reached:
        return []
    return [("action", f"{listed} reached day {reached[-1]} of {MANIFEST_VALID_DAYS}; it expires on {expires}",
             "renew it in the key console before it expires (a two-minute ceremony)")]
