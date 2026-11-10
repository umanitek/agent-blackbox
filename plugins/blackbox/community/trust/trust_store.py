"""The reader's own copy of the trust statements it verified (Community Curation C3).

Shared memory forgets after about 30 days, a busy node answers "nothing", and
anyone can publish junk beside a curator's statement. So what the network
shows at any one moment is not the state of record for trust — this file is:
``$BLACKBOX_HOME/community_trust.json`` holds, per community graph, the key
manifests and the CURRENT curator statements this node has verified, as the
signed rows themselves.

Two properties make that safe:

* nothing in the file is trusted for being there — every row is verified
  again, against the pinned roots and the effective manifest, each time it is
  loaded into a view. Editing the file can only remove trust, never add it;
* trust only moves forward — a listing ends on its signed expiry day or by a
  signed delisting, a verdict by a newer signed verdict. A statement that is
  merely ABSENT from one read stays. Because the highest sequence number per
  statement is kept, an old statement replayed later cannot undo a newer one.

The file also remembers which enforcement-raising statements this node has
ADMITTED and on which of its own days, which the daily cap on raising
statements uses (:mod:`.raising_budget`): the first read of a node is a
baseline, exempt.

It also remembers, per graph, the key manifest this node has ACTED ON once that
manifest's time-lock passed (``effective_order`` + ``effective_hash``, D31): a
later conflict at or below that order can never move the reader back
(:func:`.manifests.effective_manifest`). The verified graph's entry carries only
this field, and the graph migrations (T2): the root-signed rows naming a
successor graph and the migration this node FOLLOWS once its time-lock passed
(``successor``, sticky the same way — :mod:`.migrations`).

It holds only statements that are public in the community graph (curator keys,
reporter keys and addresses, threat identifiers) — nothing about this
operator. It is rebuilt from the network if deleted.

Pattern: Repository — one class, one lock, atomic write; pure pruning function.

Usage::

    store = TrustStore()
    stored = store.load(graph)                         # StoredTrust (empty when unknown)
    ...verify stored.manifests + stored.statements + fresh rows...
    store.remember(graph, verified_manifest_rows, verified_statement_rows, admitted=admission.admitted)
    store.remember_effective(graph, order, content_hash)   # the sticky manifest (manifests.sticky_after)
    store.remember_migrations(graph, verified_migration_rows, successor, keep_orders=[freeze])   # T2
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import date, datetime, UTC
from pathlib import Path
from typing import Callable, Collection, Iterable, Mapping, Optional

from ...kernel import constants, signing, threat_ids, yaml_files
from ...kernel.bounded_files import read_json_object
from ...kernel.signing import CuratorStatement

logger = logging.getLogger(__name__)

_STORE_FILE = "community_trust.json"
#: A statement signed longer ago than this is dropped (the longest community
#: lifetime is 460 days, the longest listing 366).
MAX_STATEMENT_AGE_DAYS = 500
#: Bounds: statements and manifests kept per graph, and how many pauses (the
#: "same two keys cannot chain pauses" rule needs the previous ones).
MAX_STORED_STATEMENTS = 20_000
MAX_STORED_MANIFESTS = 8
MAX_STORED_MIGRATIONS = 8
PAUSES_KEPT = 4
#: Statement kinds where each curator KEY has its own current statement.
_PER_KEY_KINDS = frozenset({CuratorStatement.HEARTBEAT.value, CuratorStatement.AWAY.value})

Row = dict[str, str]


@dataclass(frozen=True)
class StoredSuccessor:
    """The graph migration this node follows once its time-lock passed (T2):
    its ``order`` (root epoch, sequence) and ``content_hash`` — the sticky pair
    (:func:`.migrations.effective_migration`) — and, for display, the successor graph
    ``to_graph`` and the cut-off day ``from_day``. Only the pair is acted on:
    which graph is active is decided again from the verified rows every read."""

    order: tuple[int, int]
    content_hash: str
    to_graph: str = ""
    from_day: str = ""


@dataclass(frozen=True)
class StoredTrust:
    """One graph's stored trust: ``manifests`` and ``statements`` (plain rows,
    unverified until the caller checks them), ``admitted`` — the raising
    statements this node acts on and the reader-day each was admitted (by
    :func:`statement_key`; ``""`` = part of the baseline), ``baseline_until``
    — the time of the first read (None before any), and ``effective_order`` /
    ``effective_hash`` — the (root epoch, version) and content hash of the
    manifest this node acted on once its time-lock passed (None / "" before
    any, and for a store file written before T1), ``migrations`` — the
    root-signed graph-migration rows (unverified until checked) and
    ``successor`` — the migration followed (None before any, T2)."""

    manifests: tuple[Row, ...] = ()
    statements: tuple[Row, ...] = ()
    admitted: Mapping[str, str] = field(default_factory=dict)
    baseline_until: Optional[float] = None
    effective_order: Optional[tuple[int, int]] = None
    effective_hash: str = ""
    migrations: tuple[Row, ...] = ()
    successor: Optional[StoredSuccessor] = None

    @property
    def identifiers(self) -> list[str]:
        """The identifiers the stored statements are about (worth asking for again)."""
        return list(dict.fromkeys(row.get("identifier", "") for row in self.statements if row.get("identifier")))


def statement_key(row: Mapping[str, str]) -> str:
    """A short stable key for one signed statement: what was SIGNED, not how
    the row is written (KI-266). One statement can be published as many
    different texts that all verify, by anyone, with no key; they all have
    this one key, so they take one place in the store and in the daily cap.
    A row that is not a statement at all is keyed by its subject and text."""
    text = str(row.get("signedStatement", ""))
    envelope = signing.from_text(text)
    return threat_ids.stable_hash(signing.content_id(envelope) if envelope is not None else f"{row.get('r', '')}\n{text}", 20)


def _age_days(day: str, today: str) -> int:
    try:
        return (date.fromisoformat(today) - date.fromisoformat(day)).days
    except ValueError:
        return 0   # an unreadable day is kept (pruning must never remove a reduction by accident)


def current_statements(rows: Iterable[Mapping[str, str]], today: str) -> list[Row]:
    """The rows worth keeping: per (kind, identifier) — per curator key for
    heartbeats and away notices — only the highest sequence number (every row
    at that number, so ties stay decidable); the newest ``PAUSES_KEPT`` pauses;
    nothing signed more than ``MAX_STATEMENT_AGE_DAYS`` ago. Newest first,
    capped at ``MAX_STORED_STATEMENTS``. Rows must already be verified."""
    groups: dict[tuple[str, str, str], list[tuple[int, str, Row]]] = {}
    for row in rows:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is None:
            continue
        day = str(envelope.payload.get("day", ""))
        if _age_days(day, today) > MAX_STATEMENT_AGE_DAYS:
            continue
        kind = envelope.statement_type
        key_field = str(envelope.payload.get("key", "")) if kind in _PER_KEY_KINDS else ""
        plain = {"r": str(row.get("r", "")), "identifier": str(row.get("identifier", "")),
                 "signedStatement": str(row.get("signedStatement", ""))}
        groups.setdefault((kind, str(envelope.payload.get("identifier", "")), key_field), []).append(
            (envelope.sequence, day, plain))
    kept: list[tuple[str, Row]] = []
    for (kind, _identifier, _key), entries in groups.items():
        if kind == CuratorStatement.PAUSE.value:
            numbers = sorted({sequence for sequence, _, _ in entries}, reverse=True)[:PAUSES_KEPT]
        else:
            numbers = [max(sequence for sequence, _, _ in entries)]
        kept.extend((day, row) for sequence, day, row in entries if sequence in numbers)
    kept.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in kept[:MAX_STORED_STATEMENTS]]


class TrustStore:
    """``$BLACKBOX_HOME/community_trust.json`` — see the module docstring.
    Instances are cheap and share ONE lock, so every read-modify-write of the
    file in this process is serialised whichever instance does it."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._clock = clock

    def load(self, graph: str) -> StoredTrust:
        """What this node has stored for *graph* (empty when nothing, or the file is unreadable)."""
        with self._lock:
            return self._entry(self._read(), graph)

    def remember(self, graph: str, manifests: Iterable[Mapping[str, str]],
                 statements: Iterable[Mapping[str, str]], *, admitted: Optional[Mapping[str, str]] = None,
                 keep_orders: Iterable[tuple[int, int]] = ()) -> StoredTrust:
        """Replace *graph*'s stored trust with these VERIFIED rows, pruned to
        the current ones, and with *admitted* (the raising statements acted on
        — kept only for rows that are kept). Manifest rows at *keep_orders*
        (the freeze, :func:`.manifests.freeze_order`) and at the sticky order
        survive the newest-only pruning. Writes only when something
        changed. Fail-open: an unwritable home only costs the memory, never
        the read."""
        with self._lock:
            data = self._read()
            before = self._entry(data, graph)
            now = self._clock()
            today = datetime.fromtimestamp(now, UTC).date().isoformat()
            kept = current_statements(statements, today)
            keys = {statement_key(row) for row in kept}
            source = before.admitted if admitted is None else admitted
            manifest_rows = _newest_signed_rows(manifests, MAX_STORED_MANIFESTS,
                                                keep_orders={before.effective_order, *keep_orders})
            after = replace(before, manifests=tuple(manifest_rows), statements=tuple(kept),
                            admitted={key: day for key, day in source.items() if key in keys},
                            baseline_until=before.baseline_until if before.baseline_until is not None else now)
            if after != before:
                self._put(data, graph, after)
            return after

    def remember_effective(self, graph: str, order: Optional[tuple[int, int]], content_hash: str) -> StoredTrust:
        """Record the manifest this node acts on for *graph* once its time-lock
        has passed (:func:`.manifests.sticky_after` decides). The sticky order
        only moves forward: a lower *order* is ignored. Writes only on change."""
        with self._lock:
            data = self._read()
            before = self._entry(data, graph)
            if order is None or (before.effective_order is not None and tuple(order) <= before.effective_order):
                return before
            after = replace(before, effective_order=(int(order[0]), int(order[1])), effective_hash=str(content_hash))
            self._put(data, graph, after)
            return after

    def remember_migrations(self, graph: str, rows: Iterable[Mapping[str, str]],
                            successor: Optional[StoredSuccessor], *,
                            keep_orders: Iterable[tuple[int, int]] = ()) -> StoredTrust:
        """Replace *graph*'s stored graph-migration rows with these VERIFIED
        rows (the newest ``MAX_STORED_MIGRATIONS``, plus every row at the
        followed order and at *keep_orders* — the freeze), and record
        *successor* when it is newer than the one stored (the sticky order only
        moves forward; None keeps the stored one). Writes only on change."""
        with self._lock:
            data = self._read()
            before = self._entry(data, graph)
            sticky = before.successor
            if successor is not None and (sticky is None or successor.order > sticky.order):
                sticky = successor
            kept = _newest_signed_rows(rows, MAX_STORED_MIGRATIONS,
                                       keep_orders={sticky.order if sticky else None, *keep_orders})
            after = replace(before, migrations=tuple(kept), successor=sticky)
            if after != before:
                self._put(data, graph, after)
            return after

    def forget(self, graph: Optional[str] = None) -> None:
        """Drop one graph's stored trust, or all of it (tests, and a graph the operator left)."""
        with self._lock:
            data = self._read()
            if graph is None:
                data = {}
            else:
                data.get("graphs", {}).pop(graph, None)
            self._write(data)

    # -- file -------------------------------------------------------------

    def _put(self, data: dict[str, object], graph: str, entry: StoredTrust) -> None:
        data.setdefault("graphs", {})[graph] = {
            "manifests": list(entry.manifests), "statements": list(entry.statements),
            "admitted": dict(entry.admitted), "baseline_until": entry.baseline_until,
            "effective_order": list(entry.effective_order) if entry.effective_order else None,
            "effective_hash": entry.effective_hash, "migrations": list(entry.migrations),
            "successor": _successor_json(entry.successor)}
        self._write(data)

    @staticmethod
    def _entry(data: Mapping[str, object], graph: str) -> StoredTrust:
        try:
            entry = dict(dict(data.get("graphs") or {}).get(graph) or {})
            baseline = entry.get("baseline_until")
            return StoredTrust(
                manifests=tuple(_plain_rows(entry.get("manifests"))),
                statements=tuple(_plain_rows(entry.get("statements"))),
                admitted={str(k): str(v) for k, v in dict(entry.get("admitted") or {}).items()},
                baseline_until=float(baseline) if baseline is not None else None,
                effective_order=_order(entry.get("effective_order")),
                effective_hash=str(entry.get("effective_hash") or "") if _order(entry.get("effective_order")) else "",
                migrations=tuple(_plain_rows(entry.get("migrations"))),
                successor=_successor(entry.get("successor")))
        except (TypeError, ValueError):
            return StoredTrust()

    def _read(self) -> dict[str, object]:
        return read_json_object(self._path) or {}   # missing or unreadable: rebuilt from the network

    def _write(self, data: Mapping[str, object]) -> None:
        try:
            yaml_files.atomic_write(self._path, json.dumps({"version": 1, **dict(data)}))
        except OSError as exc:
            logger.warning("blackbox: could not save the community trust store (%s)", exc)


def _plain_rows(value: object) -> list[Row]:
    rows: list[Row] = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict):
            rows.append({"r": str(item.get("r", "")), "identifier": str(item.get("identifier", "")),
                         "signedStatement": str(item.get("signedStatement", ""))})
    return rows


def _order(value: object) -> Optional[tuple[int, int]]:
    """A stored (root epoch, version), or None when absent or malformed (an
    edited file only loses the sticky memory, never invents one higher)."""
    if isinstance(value, list) and len(value) == 2 and all(isinstance(part, int) and not isinstance(part, bool) for part in value):
        return int(value[0]), int(value[1])
    return None


def _successor_json(successor: Optional[StoredSuccessor]) -> Optional[dict[str, object]]:
    if successor is None:
        return None
    return {"order": list(successor.order), "content_hash": successor.content_hash,
            "to_graph": successor.to_graph, "from_day": successor.from_day}


def _successor(value: object) -> Optional[StoredSuccessor]:
    """A stored successor, or None when absent or malformed (an edited file
    only loses the sticky memory, never invents one)."""
    if not isinstance(value, dict):
        return None
    order = _order(value.get("order"))
    content = value.get("content_hash")
    if order is None or not isinstance(content, str) or not content:
        return None
    return StoredSuccessor(order, content, str(value.get("to_graph") or ""), str(value.get("from_day") or ""))


def _newest_signed_rows(rows: Iterable[Mapping[str, str]], limit: int,
                        keep_orders: Collection[Optional[tuple[int, int]]] = ()) -> list[Row]:
    """The newest *limit* root-signed rows (key manifests or graph migrations)
    by (root epoch, version), plus every row at *keep_orders* (the sticky one
    and the freeze): a flood of conflicting higher versions must not push the
    statement this node acts on, or the conflict that froze it, out of the store."""
    ordered: list[tuple[tuple[int, int], Row]] = []
    for row in rows:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is not None:
            ordered.append(((envelope.root_epoch, envelope.sequence),
                            {"r": str(row.get("r", "")), "identifier": "",
                             "signedStatement": str(row.get("signedStatement", ""))}))
    ordered.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in ordered[:limit]] + [row for order, row in ordered[limit:] if order in keep_orders]


def held_manifest_texts(graph: str) -> tuple[str, ...]:
    """The signed key manifests this node holds for *graph*, as texts (each was
    verified against the pinned root when it was stored) — the chain an export
    bundle carries so a receiver can check everything from the root down."""
    return tuple(sorted(row["signedStatement"] for row in TrustStore().load(graph).manifests if row.get("signedStatement")))


def manifest_orders(rows: Iterable[Mapping[str, str]]) -> list[tuple[int, int]]:
    """The (root epoch, version) of each stored manifest row — what the next lookup probes beyond."""
    orders = []
    for row in rows:
        envelope = signing.from_text(row.get("signedStatement", ""))
        if envelope is not None:
            orders.append((envelope.root_epoch, envelope.sequence))
    return orders
