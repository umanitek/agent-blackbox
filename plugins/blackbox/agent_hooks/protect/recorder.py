"""The bookkeeping of hook events, done after the agent has its answer (KI-552).

A hook waits for Blackbox's verdict; it does not need to wait while Blackbox writes the audit
log, the per-agent state and the instance timeline. ``POST /api/agent-hooks/event`` therefore
answers with the verdict and hands the rest to this ONE worker thread, which does it in arrival
order (a session's events stay in order). Measured on a throttled dashboard with 40 hook events
a second (2026-11-22): the bookkeeping, mostly the process lookups and state rewrites behind
shared locks, was what kept hooks waiting for seconds.

Bounded: at most :data:`MAX_PENDING` jobs wait. When that many are waiting, a new job is done
on the caller's thread instead (back-pressure) — slower, but no record is ever dropped.

Pattern: **Active Object** (one daemon thread with a queue), like ``notify.deliver.Pump``.

Usage::

    from . import recorder
    recorder.submit(lambda: bookkeep(judged))   # returns at once
    recorder.settle(5.0)                        # tests, shutdown: wait until all is written
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable

logger = logging.getLogger(__name__)

#: The most jobs that wait for the worker before a caller does its own (back-pressure).
MAX_PENDING = 10_000

Job = Callable[[], None]
_jobs: queue.Queue[Job] = queue.Queue(maxsize=MAX_PENDING)
_started = threading.Lock()
_worker: dict[str, threading.Thread | None] = {"thread": None}


def _run(job: Job) -> None:
    try:
        job()
    except Exception:   # health: allow BLE001 -- bookkeeping that fails never stops the next event's
        logger.warning("blackbox agent hooks: an event could not be recorded", exc_info=True)


def _loop() -> None:
    while True:
        job = _jobs.get()
        try:
            _run(job)
        finally:
            _jobs.task_done()


def _ensure_worker() -> None:
    with _started:
        thread = _worker["thread"]
        if thread is None or not thread.is_alive():
            thread = threading.Thread(target=_loop, name="blackbox-agent-hooks-recorder", daemon=True)
            thread.start()
            _worker["thread"] = thread


def submit(job: Job) -> None:
    """Do *job* on the recorder thread, after what was submitted before it. Returns at once —
    unless :data:`MAX_PENDING` jobs already wait, when *job* is done here and now."""
    _ensure_worker()
    try:
        _jobs.put_nowait(job)
    except queue.Full:
        _run(job)


def settle(timeout: float) -> bool:
    """Wait until every submitted job is done (True), or *timeout* seconds (False)."""
    deadline = time.monotonic() + max(0.0, timeout)
    with _jobs.all_tasks_done:
        while _jobs.unfinished_tasks:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            _jobs.all_tasks_done.wait(left)
    return True

