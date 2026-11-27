"""The dashboard's agent sweep: keep Blackbox hooked into the agents it may protect, every few seconds.

Moved out of ``server.py``'s ``create_app`` closure (review 2026-11-26) so its state — the targets
seen last round and when the last full pass ran — lives in one small object, and so it takes the one
attach lock (``attach.ATTACH_LOCK``) that every other attach path in this process takes too: the
per-agent switch, "protect every agent" and ``blackbox attach`` can no longer write an agent's plugin
folder or config while a sweep does.

Which targets a round may attach is ``attach.automatic_targets`` (one policy): with ``auto_attach``
off (the default) nothing new is ever attached and a reconcile (``force`` = the manual refresh, or
every :data:`RECONCILE_INTERVAL_S`) only re-hooks targets already attached; with it on, new targets
too. Never one the operator switched off. Fail-open per target.

Usage::

    sweep = AgentRescan(stopped=lambda: state["stop"])
    threading.Thread(target=sweep.loop, daemon=True).start()
    sweep.once(force=True)          # the manual refresh: the rows it touched
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from ... import attach
from ...kernel.config import load_blackbox_config

logger = logging.getLogger(__name__)

#: How often the background sweep looks for new or vanished agents.
INTERVAL_S = 5.0
#: How often a sweep re-hooks every target it may (the self-heal), even with nothing new found.
RECONCILE_INTERVAL_S = 60.0
#: How often the loop's wait checks whether the dashboard is stopping.
_STOP_CHECK_S = 0.1


class AgentRescan:
    """One dashboard's sweep state: the targets found last round and when the last full pass ran.

    *stopped* is the dashboard's "shutting down" flag; :meth:`loop` returns soon after it reads true."""

    def __init__(self, stopped: Callable[[], bool]) -> None:
        self._stopped = stopped
        self._known: set[tuple[str, str]] = set()
        self._last_reconcile = 0.0

    def once(self, *, force: bool = False) -> list[dict[str, Any]]:
        """One round: discover, choose (``attach.automatic_targets``), attach. Returns the attach
        row of each target it touched. Holds ``attach.ATTACH_LOCK`` for the whole round, so a target
        switched off meanwhile is never re-attached by a round already deciding."""
        with attach.ATTACH_LOCK:
            current: set[tuple[str, str]] = {("hermes", str(home)) for home in attach.discover_hermes_homes()}
            current |= {("openclaw", str(workspace)) for workspace in attach.discover_openclaw_workspaces()}
            now = time.monotonic()
            reconcile = force or now - self._last_reconcile >= RECONCILE_INTERVAL_S
            targets = attach.automatic_targets(current, self._known, reconcile=reconcile,
                                               auto_attach=load_blackbox_config().auto_attach)
            if reconcile:
                self._last_reconcile = now
            touched = attach.protect_automatically(targets)   # notes each newly protected agent
            for kind, target in self._known - current:
                logger.info("blackbox rescan: %s workspace vanished at %s", kind, target)
            self._known = current
            return touched

    def loop(self) -> None:
        """Every :data:`INTERVAL_S` seconds, one :meth:`once`, until *stopped*. Do NOT pre-seed the
        known targets: attach is idempotent, so the first round walks every workspace and self-heals
        anything the CLI-level attach missed."""
        while not self._stopped():
            try:
                self.once()
            except Exception:  # health: allow BLE001 -- fail open: one broken round never stops the sweep
                logger.debug("blackbox rescan: iteration failed", exc_info=True)
            for _ in range(int(INTERVAL_S / _STOP_CHECK_S)):
                if self._stopped():
                    return
                time.sleep(_STOP_CHECK_S)
