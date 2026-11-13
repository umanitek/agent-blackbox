"""When the dashboard's ruleset worker runs its first refresh (KI-205).

The installer performs an authoritative catch-up before it starts the
dashboard, so a dashboard that finds a compiled generation waits one full
``sync_interval`` before repeating that expensive transfer. A dashboard that
finds NOTHING compiled (a ``--skip-dkg`` install, a wiped home) must not sit
on "never compiled" for an hour: it refreshes after the short empty-ruleset
retry instead.

After each refresh the worker waits for whichever comes first: one full
``sync_interval`` from the start of that refresh, or the moment the compiled
ruleset itself asks to be refreshed. The ruleset carries that schedule
(:meth:`Ruleset.refresh_due` — earlier while the verified graph is still
arriving or the ruleset came back empty, KI-288), so the worker and an
agent's own hooks follow ONE schedule instead of the worker sleeping an hour
behind a node that is still downloading the graph.

Usage::

    delay = sync_timing.initial_sync_delay(cfg, ruleset.peek(cfg), min_s, empty_retry_s)
    wait = sync_timing.next_sync_delay(cfg, ruleset.peek(cfg), elapsed_s, min_s)
    stop = sync_timing.wait_or_wake(wait, stopped, wake=lambda: watch.check() and ruleset.request_refresh_now(cfg))
"""

from __future__ import annotations

import logging
import time
import math
from datetime import datetime
from typing import Any, Callable

logger = logging.getLogger(__name__)


def initial_sync_delay(cfg: Any, cached: Any, min_retry_s: float, empty_retry_s: float) -> float:
    """Seconds the worker sleeps before its first refresh.

    Never compiled, or compiled with no rules (a fresh install: setup compiles before the node has
    any graph): the short empty-ruleset retry. Compiled: whatever the
    ruleset's own schedule asks for — a generation compiled just now waits one
    sync_interval as before, but one that asked for an early refresh (the
    verified graph still arriving, KI-288) gets it. Before, a dashboard
    (re)started after the installer compiled the first asset waited a full hour
    with the node still downloading (bench bb-ours, 2026-10-08: 1,000 rules
    for an hour while 100+ assets landed).
    """
    never_compiled = not float(getattr(cached, "synced_at", 0.0) or 0.0)
    if never_compiled or not _holds_rules(cached):
        return max(min_retry_s, empty_retry_s)
    return next_sync_delay(cfg, cached, 0.0, min_retry_s)


def _holds_rules(cached: Any) -> bool:
    """Whether the compiled ruleset holds any rule. Setup compiles once while the node is still
    empty, so a fresh home has a timestamp and no rules; counting that as "compiled" put the first
    sync an hour away (judge-path test, bb-judge-2, 2026-11-07). The worker's loop already retries
    soon while the verified tier is empty; the first wait now follows the same rule."""
    try:
        return sum(cached.counts().values()) > 0
    except (AttributeError, TypeError, ValueError):
        return False


def next_sync_delay(cfg: Any, cached: Any, elapsed_s: float, min_retry_s: float) -> float:
    """Seconds the worker sleeps after a refresh that took *elapsed_s*.

    *cached* is the ruleset that refresh left (``ruleset.peek(cfg)``);
    ``cached.refresh_due(sync_interval)`` is when it wants the next refresh.
    """
    interval = max(1.0, float(getattr(cfg, "sync_interval", 0) or 1))
    period_left = interval - elapsed_s
    if float(getattr(cached, "synced_at", 0.0) or 0.0):
        period_left = min(period_left, cached.refresh_due(interval) - time.time())
    return max(min_retry_s, period_left)


def sync_time(value: Any) -> float:
    """A sync-state time as epoch seconds, 0.0 when missing or unreadable — THE one parse: an ISO
    string with a zone, epoch seconds, or epoch milliseconds (DKG job timestamps use them)."""
    try:
        if isinstance(value, str) and "T" in value:
            parsed = datetime.fromisoformat(value)
            value = parsed.timestamp() if parsed.tzinfo else 0
        value = float(value or 0)
        if value > 100_000_000_000:   # epoch milliseconds
            value /= 1000
        return value if math.isfinite(value) and value > 0 else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def catchup_supersedes_failure(catchup: Any, transfer: Any) -> bool:
    """A provably newer live job supersedes the previous attempt's error only."""
    if str(catchup.get("status")).lower() not in {"queued", "running"} or str(transfer.get("status")).lower() != "failed":
        return False
    failed = sync_time(transfer.get("updated_at"))
    return failed > 0 and sync_time(catchup.get("startedAt")) > failed


def wait_or_wake(seconds: float, stopped: Callable[[], bool], wake: Callable[[], bool], tick_s: float = 0.1,
                 clock: Callable[[], float] = time.time) -> bool:
    """Sleep up to *seconds* in *tick_s* steps, ending early when *wake* says a
    refresh should start now (new verified assets on the node,
    :class:`..ruleset.GrowthWatch`). Returns True when *stopped* asked the loop
    to end, False when the wait is over (elapsed or woken). *wake* is offered
    every tick and must be cheap (GrowthWatch rate-limits itself); an
    exception from it is logged and the wait simply continues (fail-open).

    The wait also ends when *clock* (the wall clock) passes its deadline. A
    machine that sleeps freezes this process, so counting ticks alone resumed
    the old countdown after wake: a laptop that slept overnight showed "my
    node is stale" for up to another *seconds* (Mac, 2026-10-18). The wall
    clock keeps running through sleep, so a sync that fell due while the
    machine slept starts at the first tick after wake. The tick count stays
    the upper bound, so a clock set backwards can never stretch the wait."""
    deadline = clock() + seconds
    for _ in range(int(seconds / tick_s)):
        if stopped():
            return True
        if clock() >= deadline:
            return False
        try:
            if wake():
                return False
        except Exception as exc:   # a broken probe must never stop the sync loop
            logger.warning("blackbox: verified growth check failed: %s", exc)
        time.sleep(tick_s)
    return stopped()
