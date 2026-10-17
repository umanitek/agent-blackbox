"""The community pulse keeps beating while the dashboard runs, browser or not (KI-283).

The pulse is the cheap beat between full refreshes: it keeps the node's
community membership alive (the verified graph's subscription with its shared
memory) and pulls new community statements into the rules within ~20 s. It
used to run only when an agent acted (``ruleset.get``) or a browser polled
``/api/health`` — so an idle node with no dashboard tab open never checked its
membership and saw community reports only at the hourly refresh (bench v21-b,
2026-10-06). The dashboard is the node's long-lived
process, so it drives the beat itself.

Pattern: a small Active Object — one daemon thread owned by :class:`PulseDriver`,
started and stopped by the dashboard's lifecycle hooks. ``ruleset.pulse`` is
already self-limiting (it beats only when due and never blocks), so the loop
just offers it a chance every ``community_poll_interval`` seconds.

Usage::

    driver = PulseDriver(beat=beat_once, interval=poll_interval)
    driver.start()      # on dashboard startup
    driver.stop()       # on shutdown
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

#: How long the loop waits when the pulse is switched off (interval 0), before
#: looking at the setting again — a later config edit takes effect without a restart.
IDLE_RECHECK_SECONDS = 60.0
#: Never spin faster than this, whatever the configured interval says.
MIN_INTERVAL_SECONDS = 5.0


def beat_once() -> None:
    """Offer the pulse one beat with the current config (it decides if it is due)."""
    from .. import ruleset
    from ..kernel.config import load_blackbox_config
    ruleset.pulse(load_blackbox_config())


def poll_interval() -> float:
    """The configured ``community_poll_interval`` in seconds (0 = pulse off)."""
    from ..kernel.config import load_blackbox_config
    return float(getattr(load_blackbox_config(), "community_poll_interval", 0) or 0)


class PulseDriver:
    """Calls *beat* every *interval()* seconds on one daemon thread until stopped.

    *beat* and *interval* are injected (the defaults are :func:`beat_once` and
    :func:`poll_interval`), so tests drive it without a node. A failing beat is
    logged and the loop continues — the dashboard must never die of a pulse.
    """

    def __init__(self, beat: Optional[Callable[[], None]] = None,
                 interval: Optional[Callable[[], float]] = None) -> None:
        # None = the module's functions, looked up at each beat (not bound here),
        # so the test harness can keep real beats out of tests that start apps.
        self._beat = beat
        self._interval = interval
        self._stopping = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="blackbox-pulse-driver", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stopping.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stopping.is_set():
            wait = self._next_wait()
            if wait > 0:
                try:
                    (self._beat or beat_once)()
                except Exception as exc:  # fail-open: one bad beat never stops the loop
                    logger.warning("blackbox: community pulse beat failed: %s", exc)
            self._stopping.wait(wait if wait > 0 else IDLE_RECHECK_SECONDS)

    def _next_wait(self) -> float:
        """Seconds until the next offer; 0 means the pulse is switched off."""
        try:
            interval = float((self._interval or poll_interval)())
        except Exception as exc:
            logger.warning("blackbox: could not read the community poll interval: %s", exc)
            return MIN_INTERVAL_SECONDS
        return max(MIN_INTERVAL_SECONDS, interval) if interval > 0 else 0.0
