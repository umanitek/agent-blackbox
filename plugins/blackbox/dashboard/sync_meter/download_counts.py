"""How much of the verified graph this node holds — read in the background, never on a page poll (BB-004).

The count is one aggregate query over the node's _meta
(:func:`...ruleset.verified_download_totals`). On blackbox-dev (2026-11-27, 1,749 assets,
18.0M triples, DKG 10.1.2) it took 4.3–10.1 s, and even a bare ``COUNT`` of _meta
waited ~4.5 s in the node's store queue or came back ``STORE_SCHEDULER_BUSY``. The meter
used to run it inline with a 5 s cap on every page poll (every 10 s), so a node that was
answering and serving live lookups read as "node offline", with every number blank, and
the query itself kept the store queue full.

:class:`DownloadCountReader` takes that read off the request path:

* one read at a time, in the background, at most once per :data:`REFRESH_SECONDS`,
  with a generous :data:`QUERY_TIMEOUT_SECONDS` wait (a busy store is slow, not gone);
* the last good count is kept with WHEN it was read, so a failed or slow read shows the
  last numbers and their age, never "—" or zero (LES-011);
* a count older than :data:`FRESH_SECONDS` is *stale*: it can still be shown, but the
  meter does not call the graph "synced" on it (LES-159: only a fresh, real count
  proves done);
* only the caller decides whether the node is down (the dashboard's debounced liveness
  probe). An unreachable node is never queried, and this reader never says "offline".

Pattern: a stale-while-revalidate cache with one refresher (like the dashboard's
``NodeLiveness``). *clock* and *start* are injectable, so tests run the read inline.

Usage::

    reader = DownloadCountReader()
    reading = reader.reading(cfg, reachable=True)   # instant; starts a refresh when due
    reading.totals, reading.read_at, reading.fresh, reading.note
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from agent.memory_provider import spawn_context_thread

from ... import ruleset
from ...kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)

#: Seconds to wait for the count. It runs in the background, so a busy store gets time to
#: answer (measured 4.3–10.1 s on a 2-vCPU node holding 1,749 assets, 2026-11-27).
QUERY_TIMEOUT_SECONDS = 60.0
#: Seconds between count reads. The node moves every minute or two; the old 10 s pace
#: queued a 5–10 s query behind itself. WHY this is safe: the count is a progress
#: display, not a security bound — "synced" waits for a FRESH count (below), so a slower
#: count only delays "synced", never claims it early.
REFRESH_SECONDS = 60.0
#: A count read longer ago than this is stale: shown with its age, never taken as "synced".
#: Three refreshes, so one slow or failed read does not flip the meter.
FRESH_SECONDS = 3 * REFRESH_SECONDS


@dataclass(frozen=True)
class CountReading:
    """What the reader knows about the node's downloaded count right now.

    *totals*: the last good count (None: none read yet for this graph).
    *read_at*: epoch seconds of that count (None with *totals*).
    *fresh*: *totals* was read within :data:`FRESH_SECONDS`.
    *note*: a plain sentence when the count is missing or stale ("" when fresh).
    """

    totals: Optional[ruleset.DownloadTotals]
    read_at: Optional[float]
    fresh: bool
    note: str


def _start_thread(work: Callable[[], None]) -> None:
    # WHY spawn_context_thread: the read reaches the node with the profile's credentials
    # (kernel/host_secrets), which live in ContextVars a bare Thread would not carry.
    spawn_context_thread(target=work, name="blackbox-sync-count", daemon=True).start()


class DownloadCountReader:
    """The node's downloaded-asset count, kept current in the background (see the module doc).

    One instance per dashboard process (:func:`.register_sync_meter_routes`); one lock guards
    the state. Keyed by graph id: a config switch to another graph never shows the old one's count.
    """

    def __init__(self, *, clock: Callable[[], float] = time.time,
                 start: Callable[[Callable[[], None]], None] = _start_thread,
                 read: Optional[Callable[[Any], Optional[ruleset.DownloadTotals]]] = None) -> None:
        self._clock, self._start = clock, start
        self._read = read or self._read_from_node
        self._lock = threading.Lock()
        self._graph = ""
        self._totals: Optional[ruleset.DownloadTotals] = None
        self._read_at: Optional[float] = None
        self._tried_at = -1e18   # when the last read was STARTED (paces the refreshes)
        self._failures = 0       # reads in a row that got no count
        self._busy = False

    @staticmethod
    def _read_from_node(cfg: Any) -> Optional[ruleset.DownloadTotals]:
        client = DkgClient.for_config(cfg)
        return ruleset.verified_download_totals(client, cfg.context_graph_id, timeout=QUERY_TIMEOUT_SECONDS)

    def reading(self, cfg: Any, *, reachable: bool) -> CountReading:
        """The count to show now; starts one background read when due and the node is answering.

        Never blocks on the node (unless *start* runs the work inline, as tests do)."""
        graph = str(getattr(cfg, "context_graph_id", "") or "")
        with self._lock:
            if graph != self._graph:
                self._graph, self._totals, self._read_at, self._tried_at, self._failures = graph, None, None, -1e18, 0
            due = reachable and bool(graph) and not self._busy and self._clock() - self._tried_at >= REFRESH_SECONDS
            if due:
                self._busy, self._tried_at = True, self._clock()
        if due:
            self._start(lambda: self._refresh(cfg, graph))
        with self._lock:
            return self._reading_locked()

    def _refresh(self, cfg: Any, graph: str) -> None:
        """One read (in the background); a failure keeps the last good count."""
        try:
            totals = self._read(cfg)
        except Exception:   # health: allow BLE001 -- fail open: a failed read is "no new count", the page goes on
            logger.debug("blackbox: the verified download count could not be read", exc_info=True)
            totals = None
        with self._lock:
            self._busy = False
            if graph != self._graph:   # the config moved to another graph while this read ran
                return
            if totals is None:
                self._failures += 1
                if self._failures in (1, 10) or self._failures % 60 == 0:
                    logger.info("blackbox: the node did not return its verified asset count (%d read(s) in a row); "
                                "the meter keeps the last count", self._failures)
                return
            self._totals, self._read_at, self._failures = totals, self._clock(), 0

    def _reading_locked(self) -> CountReading:
        if self._totals is None or self._read_at is None:
            note = ("The node is answering but has not returned its count yet (it is busy) — trying again "
                    "every minute." if self._failures else "Counting what this node holds…")
            return CountReading(None, None, False, note)
        age = self._clock() - self._read_at
        if age <= FRESH_SECONDS:
            return CountReading(self._totals, self._read_at, True, "")
        minutes = max(1, int(age // 60))
        return CountReading(self._totals, self._read_at, False,
                            f"Showing the count from {minutes} min ago: the node is answering but busy, "
                            "so a newer count has not come back yet.")


__all__ = ["FRESH_SECONDS", "QUERY_TIMEOUT_SECONDS", "REFRESH_SECONDS", "CountReading", "DownloadCountReader"]
