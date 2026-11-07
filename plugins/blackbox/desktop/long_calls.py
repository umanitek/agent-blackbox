"""Dashboard calls that outlast Hermes Desktop's 30-second request limit (Asynchronous Request-Reply).

Desktop drops any plugin request after 30 s ("Timed out connecting to Hermes backend after
30000ms"), but an assistant turn can take up to 120 s and a Playground test up to ~90 s. So for
those routes (``dashboard_link.LONG_ROUTES``) the page does not wait on one request: it starts the
call here, gets an id back at once, and asks for the result until it is done. Each call runs on
its own daemon thread through the same :class:`~.dashboard_link.DashboardLink` (so the same
allowlist, token and timeouts apply) and its answer is kept for a few minutes.

State lives in one :class:`LongCalls` with one lock. Bounded by construction: at most
``MAX_RUNNING`` calls at once (a further start is refused with 429), and at most ``MAX_KEPT``
records, the oldest finished ones dropped first and every record dropped after ``KEEP_S``.

Usage::

    calls = LongCalls(link)
    started = calls.start("api/blackbox-chat", {"message": "What needs attention?"})
    # -> LinkAnswer(202, {"call_id": "9f2c…", "running": True})
    calls.result(started.body["call_id"])
    # -> LinkAnswer(202, {"running": True}) while it runs, then the dashboard's own answer, then 404 once expired
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .dashboard_link import LONG_ROUTES, DashboardLink, LinkAnswer

MAX_RUNNING = 3
MAX_KEPT = 24
KEEP_S = 600.0


@dataclass
class _Call:
    """One started call: when it started, and the dashboard's answer once it has one."""

    started: float
    answer: Optional[LinkAnswer] = None


class LongCalls:
    """Runs long dashboard POSTs in the background and hands back their answers by id."""

    def __init__(self, link: DashboardLink, clock: Callable[[], float] = time.monotonic) -> None:
        self._link = link
        self._clock = clock
        self._calls: dict[str, _Call] = {}
        self._lock = threading.Lock()

    def start(self, path: str, body: Any) -> LinkAnswer:
        """Start POST *path* with *body* on a background thread.

        202 ``{"call_id", "running": True}``; 404 for a route that is not a long one (those are
        answered directly); 429 while ``MAX_RUNNING`` calls are still running."""
        path = path.strip("/")
        if not (LONG_ROUTES.fullmatch(path) and DashboardLink.allowed("POST", path)):
            return LinkAnswer(404, {"error": "not a long dashboard call the Desktop page uses"})
        with self._lock:
            self._forget_expired()
            if sum(1 for call in self._calls.values() if call.answer is None) >= MAX_RUNNING:
                return LinkAnswer(429, {"error": "Blackbox is still working on earlier requests. Try again in a moment."})
            call_id = secrets.token_hex(12)
            self._calls[call_id] = _Call(started=self._clock())
            self._trim()
        threading.Thread(target=self._run, args=(call_id, path, body), name="blackbox-desktop-call", daemon=True).start()
        return LinkAnswer(202, {"call_id": call_id, "running": True})

    def result(self, call_id: str) -> LinkAnswer:
        """202 ``{"running": True}`` while the call runs, then the dashboard's answer; 404 for an unknown id."""
        with self._lock:
            self._forget_expired()
            call = self._calls.get(call_id)
        if call is None:
            return LinkAnswer(404, {"error": "That request has finished long ago or never started. Ask again."})
        return call.answer or LinkAnswer(202, {"running": True})

    def _run(self, call_id: str, path: str, body: Any) -> None:
        try:
            answer = self._link.forward("POST", path, "", body)
        except Exception as exc:   # health: allow BLE001 -- a thread's fault must still end the call, or the page waits until expiry
            answer = LinkAnswer(500, {"error": f"Blackbox could not finish that request: {type(exc).__name__}"})
        with self._lock:
            call = self._calls.get(call_id)
            if call is not None:
                call.answer = answer

    def _forget_expired(self) -> None:
        cutoff = self._clock() - KEEP_S
        for call_id in [key for key, call in self._calls.items() if call.started < cutoff]:
            del self._calls[call_id]

    def _trim(self) -> None:
        # WHY oldest finished first: a running call's thread will still write its answer, and the
        # page is waiting for it; a finished one has most likely been read already.
        finished = sorted((call.started, key) for key, call in self._calls.items() if call.answer is not None)
        while len(self._calls) > MAX_KEPT and finished:
            del self._calls[finished.pop(0)[1]]


__all__ = ["KEEP_S", "MAX_KEPT", "MAX_RUNNING", "LongCalls"]
