"""The dashboard's probes of the local DKG node: is it answering, and how is its sync.

* :class:`NodeLiveness` — the cached, debounced answer to "is the node
  answering?" that gates every node read the dashboard makes, and the log of
  its outages (KI-335).
* :func:`node_sync_probe` — one probe for ``GET /api/graph-status`` (cached by
  the route's SWR wrapper): ``None`` when the node is down, else
  ``{"node_reachable": True, "catchup": <job dict>, "subscribed": True|False|None}``:
  the verified graph's catch-up job and whether the node even LISTS that graph
  as subscribed. ``subscribed`` is ``None`` when the listing could not be read —
  unknown is not "no" (KI-215: the pair's panel counted "51 min elapsed" on a
  graph the node never followed).
* :class:`RepeatGate` — keeps a condition that persists from writing one log
  line per poll.
* :class:`NodeReadCache` — the stale-while-revalidate cache every node-backed
  read is served through, so a slow or dead node never makes a poll wait.

Log lines go to the standard ``logging`` tree; under Hermes that is the
size-capped, secret-redacting ``~/.hermes/logs/agent.log`` (WARNING also in
``errors.log``), so nothing here manages files of its own.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from ..kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)

#: Status checks in a row that must get no answer before the dashboard calls a
#: node that WAS answering offline. One slow check — the node busy sealing a
#: share — is "could not tell", not "down" (LES-011; KI-335 blanked the page
#: for one such check while the node answered queries the whole time).
FAILURES_BEFORE_OFFLINE = 2
#: A check that answers but takes longer than this is logged as slow.
SLOW_CHECK_SECONDS = 2.0
#: A condition that keeps repeating (slow checks, a long outage) is re-logged
#: at most this often.
REPEAT_LOG_SECONDS = 300.0

_LogLine = tuple[int, str, tuple[Any, ...]]


class RepeatGate:
    """Say when a repeating condition is due another log line.

    ``gate.due(key)`` is True the first time a key is seen and then at most
    once per ``interval`` seconds, so a node that is slow on every poll writes
    one line per interval instead of one per poll. Thread-safe.
    """

    def __init__(self, interval: float = REPEAT_LOG_SECONDS, clock: Callable[[], float] = time.monotonic) -> None:
        self._interval = interval
        self._clock = clock
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}

    def due(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < self._interval:
                return False
            self._last[key] = now
            return True


def _start_thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="blackbox-reach", daemon=True).start()


class NodeLiveness:
    """Cached, debounced "is the local DKG node answering?" — and the record of its outages.

    ``liveness.reachable(cfg)`` never blocks: it returns the last answer at
    once (``False`` until the first check lands) and starts a background check
    when the answer is older than ``ttl`` seconds. ``liveness.check_now(cfg)``
    runs one check in the caller's thread (the boot warm-up uses it, so the
    first reads see the node's real state).

    Debounce: a node that was answering is reported offline only after
    :data:`FAILURES_BEFORE_OFFLINE` checks in a row got no answer; before the
    first success any failure reads as offline (nothing is known to be up).

    Log lines, changes only — steady state writes nothing: first answer, every
    missed check, going offline, coming back (with how long it was gone), a
    check slower than :data:`SLOW_CHECK_SECONDS` and a continuing outage (both
    at most once per :data:`REPEAT_LOG_SECONDS`).

    *check* is ``(cfg, timeout) -> bool`` — the server passes the node's
    ``/api/status`` check through the client it uses for every other read;
    *clock* and *start* are injectable for tests. One lock guards the state.

    Usage::

        liveness = NodeLiveness(lambda cfg, t: DkgClient(url=cfg.dkg_url).reachable(timeout=t))
        if liveness.reachable(cfg):   # instant
            ...read the node...
    """

    def __init__(self, check: Callable[[Any, float], bool], *, ttl: float = 15.0,
                 timeout: float = 5.0, clock: Callable[[], float] = time.monotonic,
                 start: Callable[[Callable[[], None]], None] = _start_thread) -> None:
        self._check, self._ttl, self._timeout = check, ttl, timeout
        self._clock, self._start = clock, start
        self._lock = threading.Lock()
        self._answering: Optional[bool] = None   # None: never checked
        self._failures = 0
        self._first_failure_at: Optional[float] = None
        self._checked_at = -1e9
        self._busy = False
        self._repeats = RepeatGate(clock=clock)

    def reachable(self, cfg: Any) -> bool:
        with self._lock:
            spawn = (self._clock() - self._checked_at) >= self._ttl and not self._busy
            if spawn:
                self._busy = True
            answering = bool(self._answering)
        if spawn:
            self._start(lambda: self.check_now(cfg))
        return answering

    def check_now(self, cfg: Any) -> bool:
        started = self._clock()
        try:
            ok = bool(self._check(cfg, self._timeout))
        except Exception:  # fail open: an error is a check that got no answer
            ok = False
        lines = self._record(ok, self._clock() - started)
        for level, message, args in lines:
            logger.log(level, "blackbox dashboard: " + message, *args)
        with self._lock:
            return bool(self._answering)

    def _record(self, ok: bool, seconds: float) -> list[_LogLine]:
        """Fold one check result into the state; return the log lines it earns."""
        now = self._clock()
        with self._lock:
            was, missed = self._answering, self._failures
            self._checked_at, self._busy = now, False
            if ok:
                outage = now - self._first_failure_at if self._first_failure_at is not None else 0.0
                self._answering, self._failures, self._first_failure_at = True, 0, None
                return self._answered_lines(was, missed, seconds, outage)
            self._failures += 1
            if self._first_failure_at is None:
                self._first_failure_at = now
            if was is not True or self._failures >= FAILURES_BEFORE_OFFLINE:
                self._answering = False
            return self._missed_lines(was, seconds, now - self._first_failure_at)

    def _answered_lines(self, was: Optional[bool], missed: int, seconds: float, outage: float) -> list[_LogLine]:
        lines: list[_LogLine] = []
        if was is None:
            lines.append((logging.INFO, "DKG node answering (status check %.2f s)", (seconds,)))
        elif was is False:
            lines.append((logging.WARNING, "DKG node answering again after %.0f s offline (status check %.2f s)",
                          (outage, seconds)))
        elif missed:
            lines.append((logging.INFO, "DKG node answered again after %d missed status check(s); "
                          "the page never showed it offline (status check %.2f s)", (missed, seconds)))
        if seconds > SLOW_CHECK_SECONDS and self._repeats.due("slow"):
            lines.append((logging.WARNING, "DKG node status check slow: %.1f s (the dashboard waits up to %.0f s)",
                          (seconds, self._timeout)))
        return lines

    def _missed_lines(self, was: Optional[bool], seconds: float, outage: float) -> list[_LogLine]:
        if was is None:
            return [(logging.WARNING, "DKG node not answering at dashboard start (status check gave up after %.1f s)",
                     (seconds,))]
        if was is True and self._answering:
            return [(logging.WARNING, "DKG node status check got no answer after %.1f s "
                     "(%d of %d misses before the page shows it offline)",
                     (seconds, self._failures, FAILURES_BEFORE_OFFLINE))]
        if was is True:
            return [(logging.WARNING, "DKG node treated as offline: %d status checks in a row got no answer "
                     "(last gave up after %.1f s)", (self._failures, seconds))]
        if self._repeats.due("offline"):
            return [(logging.WARNING, "DKG node still not answering (%.0f s so far)", (outage,))]
        return []


def node_sync_probe(cfg: Any, *, reachable: bool) -> Optional[dict[str, Any]]:
    if not reachable:
        return None
    client = DkgClient.for_config(cfg)
    try:
        catchup = client.catchup_status(cfg.context_graph_id)
    except Exception:
        catchup = {}   # no job is normal on an already-settled node
    try:
        entries = client.context_graphs()
        subscribed: Optional[bool] = any(
            str(e.get("id") or "") == cfg.context_graph_id and bool(e.get("subscribed")) for e in entries
        )
    except Exception:
        subscribed = None
    return {"node_reachable": True, "catchup": catchup, "subscribed": subscribed}


class NodeReadCache:
    """Stale-while-revalidate cache for the dashboard's node-backed reads (one lock, one instance per app).

    ``get(key, producer, default, ttl=None)`` answers the cached value for *key* at once and, once it
    is older than *ttl* (``default_ttl`` when None), refreshes it on a background thread — *default*
    until the first refresh lands. *producer* runs off the request path, so it may block on the node;
    a failure keeps the last value and is logged at most once per interval per key (*log_gate*), and a
    refresh slower than *slow_seconds* is logged too.

    ``store(key, producer)`` recomputes *key* now, on the caller's thread — for a read whose input the
    request itself just changed (a Settings save changes a shield's card), so the page's next read is
    the new value. A background refresh that began before such a store never overwrites it.

        reads = NodeReadCache(default_ttl=20.0, slow_seconds=10.0, log_gate=RepeatGate())
        cards = reads.get("shields", build_cards, [], 2.0)
        reads.store("shields", build_cards)
    """

    def __init__(self, *, default_ttl: float, slow_seconds: float, log_gate: RepeatGate) -> None:
        self._default_ttl = default_ttl
        self._slow_seconds = slow_seconds
        self._log_gate = log_gate
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}   # key -> {"val", "ts"}
        self._busy: set[str] = set()

    def get(self, key: str, producer: Callable[[], Any], default: Any, ttl: Optional[float] = None) -> Any:
        now = time.monotonic()
        with self._lock:
            entry = self._state.get(key)
            fresh = entry is not None and (now - entry["ts"]) < (self._default_ttl if ttl is None else ttl)
            current = entry["val"] if entry is not None else default
            spawn = (not fresh) and (key not in self._busy)
            if spawn:
                self._busy.add(key)
        if spawn:
            threading.Thread(target=self._refresh, args=(key, producer), name="blackbox-swr", daemon=True).start()
        return current

    def store(self, key: str, producer: Callable[[], Any]) -> None:
        value = producer()
        with self._lock:
            self._state[key] = {"val": value, "ts": time.monotonic()}

    def _refresh(self, key: str, producer: Callable[[], Any]) -> None:
        started = time.monotonic()
        try:
            value = producer()
        except Exception as exc:  # fail open; logged (with its traceback) at most once per interval per key
            if self._log_gate.due(key):
                logger.warning("blackbox dashboard: node read %s failed: %s", key, exc, exc_info=True)
            value = None
        elapsed = time.monotonic() - started
        if elapsed > self._slow_seconds and self._log_gate.due("slow:" + key):
            logger.warning("blackbox dashboard: node read %s took %.1f s", key, elapsed)
        with self._lock:
            newer = self._state.get(key)
            # A value stored after this refresh began (a save's store) is newer: keep it.
            if value is not None and not (newer is not None and newer["ts"] > started):
                self._state[key] = {"val": value, "ts": time.monotonic()}
            self._busy.discard(key)
