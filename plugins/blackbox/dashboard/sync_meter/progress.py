"""Is the verified sync moving, and which step is it on? (2026-10-22)

The founder, on a fresh node: a card at 0 / 565 with nothing moving and a red
"run blackbox sync --wait" over a sync that was already running read as broken.
This module tells the steps apart in plain words (:func:`sync_phase`) and tells
"sit tight" from "stuck" (:class:`SyncProgressWatch`, one per dashboard process:
:data:`WATCH`). The meter (``sync_meter.__init__``) feeds every reading in and
serves the phase; the health poll reads :meth:`SyncProgressWatch.first_sync`.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from ...kernel import constants, yaml_files


class SyncMeter(Protocol):
    """What this module reads from one meter reading (``sync_meter.SyncMeter`` has these);
    a Protocol, so the watch needs no import of the meter (no cycle)."""

    state: str
    graph_assets: Optional[int]
    downloaded_assets: Optional[int]
    compiled_assets: Optional[int]

logger = logging.getLogger(__name__)

#: A sync whose download and compile counts have not moved for this long is STALLED.
#: A fresh node's first verified asset can take several minutes to arrive (its sync
#: queue is busy at start), so the bar sits well above that wait (bench, 2026-10-22).
STALL_SECONDS = 20 * 60


def sync_phase(meter: SyncMeter, stalled: bool) -> tuple[str, str]:
    """Pure: ``(phase, sentence)`` for the step the sync is on, in plain words.

    Usage: ``phase, text = sync_phase(meter, stalled=watch.observe(meter).stalled)``.
    "" when there is nothing to say (the node is not answering: the note already says so).
    """
    if meter.state in ("unavailable", "synced"):
        return ("synced", "") if meter.state == "synced" else ("", "")
    downloaded, total = meter.downloaded_assets or 0, meter.graph_assets
    if stalled:
        return ("stalled", f"No progress for {STALL_SECONDS // 60}+ minutes. Check that the DKG node is "
                           "running (blackbox status), then run blackbox sync --wait.")
    if total is None and downloaded == 0:
        return ("finding", "Finding Umanitek's verified threat graph on the network.")
    if downloaded == 0:
        return ("queued", f"The node found all {total:,} verified assets and is lining up the download. "
                          "On a new machine this step can take several minutes before the first asset arrives.")
    if total is None or downloaded < total:
        of_total = f" of {total:,}" if total is not None else ""
        return ("downloading", f"Downloading verified assets: {downloaded:,}{of_total}.")
    return ("compiling", f"Turning the downloaded assets into rules: {meter.compiled_assets or 0:,} of {downloaded:,}.")


@dataclass(frozen=True)
class SyncProgress:
    """What :class:`SyncProgressWatch` knows after one reading."""

    running_since: Optional[float]
    last_progress: Optional[float]
    stalled: bool


class SyncProgressWatch:
    """When this dashboard first saw the verified sync running, and when its download
    and compile counts last moved — the difference between "sit tight" and "stuck".

    One instance per dashboard process (:data:`WATCH`), fed by every meter reading and
    read by the health poll (:meth:`first_sync`); one lock. Pattern: Observer of the
    meter readings. A node that is not answering is "could not tell": never stalled,
    and the clock does not move (LES-011). The two times are kept in *store* (a small
    JSON file in the Blackbox home), so a dashboard restart does not reset "running
    30 min" to "running 1 min"; an unreadable file only costs that memory (fail-open).

    Usage::

        progress = WATCH.observe(meter)       # after each reading
        WATCH.first_sync()                    # "running" | "stalled" | ""
    """

    def __init__(self, clock: Callable[[], float] = time.time, store: Optional[Callable[[], Path]] = None) -> None:
        self._clock = clock
        self._store = store
        self._lock = threading.Lock()
        self._loaded = False
        self._since: Optional[float] = None
        self._last_change: Optional[float] = None
        self._last_counts: Optional[tuple[Optional[int], ...]] = None
        self._status = ""
        self._observed = False

    def _load(self) -> None:
        """Read the remembered times once (under the lock)."""
        if self._loaded or self._store is None:
            return
        self._loaded = True
        try:
            saved = json.loads(self._store().read_text(encoding="utf-8-sig"))
            self._since, self._last_change = float(saved["since"]), float(saved["last_change"])
            counts = saved.get("counts")
            self._last_counts = tuple(counts) if isinstance(counts, list) else None
        except (OSError, ValueError, KeyError, TypeError):
            self._since = self._last_change = None   # nothing remembered: start counting now

    def _save(self) -> None:
        """Remember the times (under the lock); a failed write only loses the memory."""
        if self._store is None:
            return
        try:
            path = self._store()
            if self._since is None:
                path.unlink(missing_ok=True)
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            yaml_files.atomic_write(path, json.dumps({"since": self._since, "last_change": self._last_change,
                                                      "counts": list(self._last_counts or ())}))
        except OSError as exc:
            logger.warning("blackbox: could not remember the sync's progress times: %s", exc)

    def observe(self, meter: SyncMeter) -> SyncProgress:
        """Record one reading; returns the running time, last progress and stall verdict."""
        now = self._clock()
        with self._lock:
            self._load()
            self._observed = True
            if meter.state == "synced":
                if self._since is not None:
                    self._since = self._last_change = self._last_counts = None
                    self._save()
                self._status = ""
                return SyncProgress(None, None, False)
            if meter.state not in ("syncing", "unknown"):   # could not tell: keep what we knew
                return SyncProgress(self._since, self._last_change, False)
            counts = (meter.downloaded_assets, meter.compiled_assets, meter.graph_assets)
            changed = self._since is None or counts != self._last_counts
            if self._since is None:
                self._since = now
            if counts != self._last_counts:
                self._last_counts, self._last_change = counts, now
            if changed:
                self._save()
            stalled = self._last_change is not None and now - self._last_change >= STALL_SECONDS
            self._status = "stalled" if stalled else "running"
            return SyncProgress(self._since, self._last_change, stalled)

    def first_sync(self) -> str:
        """"running" / "stalled" while a sync is in progress, else "" (for the health checks)."""
        with self._lock:
            return self._status

    @property
    def observed(self) -> bool:
        """Whether this process has recorded a reading yet: before it, "" means "not read", not "not syncing"."""
        with self._lock:
            return self._observed


#: The dashboard process's watch (see :class:`SyncProgressWatch`), remembered in the Blackbox home.
WATCH = SyncProgressWatch(store=lambda: constants.blackbox_home() / "sync_progress.json")
