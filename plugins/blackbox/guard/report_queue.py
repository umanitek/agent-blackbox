"""Report follow-up runs after the hook has answered, one finding set at a time.

WHY: once a finding is recorded locally, the rest of its follow-up talks to the
local node — who this node is, the private audit record, the community share.
That used to run on the hook's own thread, so the answer "block this call"
waited for the node (the audit record alone may wait 150 s). Now the hook
records the finding, hands the follow-up to this queue and answers.

Pattern: Active Object — a queue and ONE daemon worker. One worker, not a
thread per event, because the per-threat cooldown is "look, then stamp": run in
the order the hooks produced them, a repeat finds the stamp its first sighting
left. The worker starts with the first job and ends when the queue is empty;
it is a daemon, so a slow node never keeps a finished command alive.

The queue is bounded: with the node down every job waits out a timeout, and an
agent that keeps finding things must not grow memory without limit. A job that
does not fit is dropped with a WARNING — the local record was already written.

Usage::

    REPORTS.submit(lambda: follow_up(findings))   # returns at once
    REPORTS.settled(timeout_s=90)                 # tests, the Playground: wait until idle
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Callable, Optional

logger = logging.getLogger(__name__)

#: Name of the worker thread.
WORKER_NAME = "blackbox-report-followup"
#: Most finding sets that may wait at once.
MAX_WAITING = 200


class ReportQueue:
    """Runs submitted jobs in order on one daemon thread. Holds: the waiting jobs,
    how many are unfinished, and the worker; all under one lock."""

    def __init__(self, *, max_waiting: int = MAX_WAITING) -> None:
        self._max_waiting = max_waiting
        self._state = threading.Condition()
        self._waiting: deque[Callable[[], None]] = deque()
        self._unfinished = 0
        self._worker: Optional[threading.Thread] = None

    def submit(self, job: Callable[[], None]) -> bool:
        """Queue *job* and return at once; False when the queue is full (the job is dropped)."""
        with self._state:
            if len(self._waiting) >= self._max_waiting:
                logger.warning("blackbox: report follow-up queue is full (%d waiting); one finding set "
                               "keeps its local record only", len(self._waiting))
                return False
            self._waiting.append(job)
            self._unfinished += 1
            if self._worker is None:
                self._worker = threading.Thread(target=self._work, name=WORKER_NAME, daemon=True)
                self._worker.start()
        return True

    def settled(self, timeout_s: float) -> bool:
        """Wait up to *timeout_s* for every submitted job to finish; True when none is left."""
        with self._state:
            return self._state.wait_for(lambda: self._unfinished == 0, timeout_s)

    def _work(self) -> None:
        while True:
            with self._state:
                if not self._waiting:
                    self._worker = None
                    return
                job = self._waiting.popleft()
            try:
                job()
            except Exception as exc:   # health: allow BLE001 -- the worker's boundary: one failed follow-up must not end the others; findings may quote arguments, so only the class is logged
                logger.warning("blackbox: a report follow-up failed (%s)", type(exc).__name__)
            finally:
                with self._state:
                    self._unfinished -= 1
                    self._state.notify_all()


#: The process's one queue (Global Object): hooks and background checks all submit here.
REPORTS = ReportQueue()
