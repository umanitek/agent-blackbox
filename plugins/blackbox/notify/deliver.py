"""One deliverer at a time: the plugin's own native notifier, or a companion app.

A companion app, while it runs, delivers instead: it already has the system's permission and its
own window to open on a click — so it shows the feed and the plugin's notifier stays silent. It
says so with a
LEASE it renews (``claim``); when it quits the lease runs out and the plugin's notifier takes
over from the feed's ONE ``delivered`` cursor — so nothing is shown twice and nothing is lost.

:class:`Pump` is the loop the dashboard runs: each tick it collects new notices
(:mod:`.sources`), applies the person's policy (:mod:`.policy`: off / muted / quiet hours / at
most N a minute, the rest counted into one summary), publishes them to the feed and — unless
a companion app holds the lease — hands the undelivered ones to the platform notifier. A notifier that
fails never affects an agent: everything here runs on the dashboard's own thread.

Pattern: **Active Object** (one daemon thread, like ``dashboard.pulse_driver``).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import replace
from typing import Callable, Optional

from . import feed, platform, policy, wording
from .model import Delivery, Notice
from .sources import Collector

logger = logging.getLogger(__name__)

TICK_SECONDS = 2.0
#: The longest lease one claim may ask for.
MAX_LEASE_SECONDS = 120.0
#: An undelivered notice older than this is history, not news (a deliverer was away too long).
STALE_SECONDS = 10 * 60.0
_lock = threading.Lock()
_lease: dict[str, object] = {"holder": "", "until": 0.0}


def claim(holder: str, seconds: float) -> float:
    """*holder* (the app's name, e.g. ``"companion"``) delivers for the next *seconds* (≤ :data:`MAX_LEASE_SECONDS`);
    0 seconds gives the lease up. Returns when it runs out (monotonic seconds from now)."""
    seconds = max(0.0, min(float(seconds), MAX_LEASE_SECONDS))
    with _lock:
        _lease.update(holder=holder[:40] if seconds else "", until=time.monotonic() + seconds)
    return seconds


def holder() -> str:
    """Who delivers now besides the plugin's own notifier ("" = nobody: the plugin does)."""
    with _lock:
        return str(_lease["holder"]) if time.monotonic() < float(_lease["until"]) else ""   # type: ignore[arg-type]


def lane(notice: Notice) -> str:
    """Which per-minute budget *notice* draws on. An AI agent's own security notices (stopped,
    flagged, not stopped in time, root) have a budget of their own, apart from the shields' and
    from lifecycle and digest notices. WHY (KI-PENDING-b3bd8e): 30 short SSH logins used up the
    one shared budget and an agent's elevation notice was then held back."""
    if notice.category == "security":
        return "shields" if notice.kind.startswith("shield:") else "agents" if notice.agent else "security"
    return notice.category


class Limiter:
    """At most *per_minute* notices shown in any minute PER LANE (:func:`lane`); the rest are
    counted for one summary, which waits for room in a lane that overflowed."""

    def __init__(self) -> None:
        self._shown: dict[str, list[float]] = {}
        self._overflow: dict[str, int] = {}

    def _recent(self, lane_name: str, now: float) -> list[float]:
        recent = [at for at in self._shown.get(lane_name, []) if now - at < 60.0]
        self._shown[lane_name] = recent
        return recent

    def allow(self, now: float, per_minute: int, lane_name: str = "security") -> bool:
        recent = self._recent(lane_name, now)
        if len(recent) < per_minute:
            recent.append(now)
            return True
        self._overflow[lane_name] = self._overflow.get(lane_name, 0) + 1
        return False

    def summary_due(self, now: float, per_minute: int) -> int:
        """How many were held back, once a lane that overflowed has room to say so (the summary
        takes that room; then the count starts again)."""
        roomy = [name for name in self._overflow if len(self._recent(name, now)) < per_minute]
        if not roomy:
            return 0
        self._shown[roomy[0]].append(now)
        count = sum(self._overflow.values())
        self._overflow.clear()
        return count


def _native(notice: Notice, details: bool) -> Delivery:
    """The plugin's own notifier (:mod:`.platform`), with the detail only when the person chose it."""
    body = f"{notice.body} {notice.detail}".strip() if details and notice.detail else notice.body
    return platform.send(notice.title, body, notice.level, notice.id)


class Pump:
    """Collect → policy → feed → deliver, every :data:`TICK_SECONDS`, until stopped.

    *collector*, *send* and *read_policy* are injected for tests; the defaults are the real ones.
    *send* answers a :class:`.model.Delivery`; its outcome is kept on the notice in the feed, so
    the history says what became of each one (never "shown" when the system did not take it)."""

    def __init__(self, collector: Optional[Collector] = None,
                 send: Optional[Callable[[Notice, bool], Delivery]] = None,
                 read_policy: Optional[Callable[[], policy.Policy]] = None) -> None:
        self._collector = collector or Collector()
        self._send = send
        self._read_policy = read_policy or policy.read
        self._limiter = Limiter()
        self._stopping = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def step(self, now: Optional[float] = None) -> list[Notice]:
        """One tick; returns the notices published. Never raises."""
        now = time.time() if now is None else now
        current = self._read_policy()
        published = []
        for notice in self._collector.collect(now, current.digest_minutes if current.digest else 0):
            why = policy.held(current, notice, now)
            if why == "off":
                continue
            if not why and not self._limiter.allow(now, current.per_minute, lane(notice)):
                why = "rate"
            kept = feed.publish(replace(notice, deliver=not why, held=why))
            if kept is not None:
                published.append(kept)
        held_back = self._limiter.summary_due(now, current.per_minute)
        if held_back and current.enabled:
            kept = feed.publish(wording.summary(held_back, now))
            if kept is not None:
                published.append(kept)
        self.deliver(now, current)
        return published

    def deliver(self, now: float, current: policy.Policy) -> int:
        """Show what the feed holds past the delivered cursor — unless a companion app holds the lease.
        Returns how many were shown."""
        if holder():
            return 0
        if self._send is None and not feed.delivers_here():
            feed.mark_delivered(feed.top())   # not an installed Blackbox: the history only, never the screen
            return 0
        send = self._send or _native
        outcomes: dict[int, str] = {}
        for notice in feed.since(feed.delivered()):
            if notice.deliver and now - notice.ts < STALE_SECONDS:
                try:
                    outcomes[notice.seq] = send(notice, current.details).outcome
                except Exception:   # health: allow BLE001 -- a notifier fault is never an agent's problem
                    outcomes[notice.seq] = "not-shown"
                    logger.debug("blackbox notify: the notifier failed", exc_info=True)
            feed.mark_delivered(notice.seq)
        feed.note_delivery(outcomes)
        return sum(outcome != "not-shown" for outcome in outcomes.values())

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="blackbox-notify-pump", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stopping.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stopping.wait(TICK_SECONDS):
            try:
                self.step()
            except Exception:   # health: allow BLE001 -- the dashboard never dies of a notification
                logger.debug("blackbox notify: a tick failed", exc_info=True)
