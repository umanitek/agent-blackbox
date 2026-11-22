"""One deliverer at a time: the plugin's own native notifier, or Blackbox Desktop.

Blackbox Desktop, while it runs, already has the system's permission and its own window to open
on a click — so it shows the feed and the plugin's notifier stays silent. Desktop says so with a
LEASE it renews (``claim``); when it quits the lease runs out and the plugin's notifier takes
over from the feed's ONE ``delivered`` cursor — so nothing is shown twice and nothing is lost.

:class:`Pump` is the loop the dashboard runs: each tick it collects new notices
(:mod:`.sources`), applies the person's policy (:mod:`.policy`: off / muted / quiet hours / at
most N a minute, the rest counted into one summary), publishes them to the feed and — unless
Desktop holds the lease — hands the undelivered ones to the platform notifier. A notifier that
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
from .model import Notice
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
    """*holder* (``"desktop"``) delivers for the next *seconds* (≤ :data:`MAX_LEASE_SECONDS`);
    0 seconds gives the lease up. Returns when it runs out (monotonic seconds from now)."""
    seconds = max(0.0, min(float(seconds), MAX_LEASE_SECONDS))
    with _lock:
        _lease.update(holder=holder[:40] if seconds else "", until=time.monotonic() + seconds)
    return seconds


def holder() -> str:
    """Who delivers now besides the plugin's own notifier ("" = nobody: the plugin does)."""
    with _lock:
        return str(_lease["holder"]) if time.monotonic() < float(_lease["until"]) else ""   # type: ignore[arg-type]


class Limiter:
    """At most *per_minute* notices shown in any minute; the rest are counted for one summary."""

    def __init__(self) -> None:
        self._shown: list[float] = []
        self.overflow = 0

    def allow(self, now: float, per_minute: int) -> bool:
        self._shown = [at for at in self._shown if now - at < 60.0]
        if len(self._shown) < per_minute:
            self._shown.append(now)
            return True
        self.overflow += 1
        return False

    def summary_due(self, now: float, per_minute: int) -> int:
        """How many were held back, once there is room to say so (then the count starts again)."""
        self._shown = [at for at in self._shown if now - at < 60.0]
        if self.overflow and len(self._shown) < per_minute:
            count, self.overflow = self.overflow, 0
            self._shown.append(now)
            return count
        return 0


class Pump:
    """Collect → policy → feed → deliver, every :data:`TICK_SECONDS`, until stopped.

    *collector*, *send* and *read_policy* are injected for tests; the defaults are the real ones."""

    def __init__(self, collector: Optional[Collector] = None,
                 send: Optional[Callable[[Notice, bool], bool]] = None,
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
            if not why and not self._limiter.allow(now, current.per_minute):
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
        """Show what the feed holds past the delivered cursor — unless Desktop holds the lease.
        Returns how many were shown."""
        if holder():
            return 0
        shown = 0
        for notice in feed.since(feed.delivered()):
            if notice.deliver and now - notice.ts < STALE_SECONDS:
                send = self._send or (lambda item, details: platform.send(
                    item.title, f"{item.body} {item.detail}".strip() if details and item.detail else item.body, item.level, item.id))
                try:
                    shown += bool(send(notice, current.details))
                except Exception:   # health: allow BLE001 -- a notifier fault is never an agent's problem
                    logger.debug("blackbox notify: the notifier failed", exc_info=True)
            feed.mark_delivered(notice.seq)
        return shown

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
