"""Notice, within seconds, that the node holds a verified asset the last refresh did not read.

WHY: the full verified refresh is heavy — it reads the small tiers of every
confirmed asset (LES-040) — so it runs on the hourly ``sync_interval``. The
node, though, receives a newly published asset within about 30 s, and a new
threat or a correction must not wait up to an hour to take effect (Amos,
2026-10-12: the core threat graph stays current in real time). One aggregate
count on the node's ``_meta`` (:func:`.reader.verified_download_totals`, the
query the dashboard's sync meter already runs) is cheap enough to ask every
:data:`PROBE_EVERY_SECONDS`; only growth since the last refresh pays for a
full one.

Three outcomes (LES-011): the node holds MORE confirmed assets than the last
refresh listed (act), the same or fewer (do nothing), or one side could not
say (do nothing — a failed probe is never read as growth or as "no change").
No refresh storm: one trigger per new count, and never sooner than
:data:`MIN_TRIGGER_GAP_SECONDS` after the previous trigger. The hourly
refresh stays the backstop for anything this misses.

Pattern: a polling Observer with its probe, its baseline and its clock
injected, so the decision is tested without a node. State lives on the
instance; one instance per long-lived loop (the dashboard's ruleset worker).

Usage::

    watch = GrowthWatch.for_config(load_blackbox_config)
    ...
    if watch.check():                       # cheap; rate-limits itself
        ruleset.request_refresh_now(cfg)    # the worker's next look refreshes
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from ...kernel.dkg_client import DkgClient
from .reader import progress, verified_download_totals

#: How often the node is asked for its confirmed-asset count.
PROBE_EVERY_SECONDS = 30.0
#: The fewest seconds between two growth-triggered refreshes.
MIN_TRIGGER_GAP_SECONDS = 120.0
#: The probe's own deadline: a slow answer is "could not tell", never a stall.
PROBE_TIMEOUT_SECONDS = 10.0

#: Returns a count, or None when it could not tell.
CountSource = Callable[[], Optional[int]]


class GrowthWatch:
    """Decides when verified-graph growth on the node warrants a refresh now.

    *node_assets* — the confirmed assets the node holds now (None = could not tell).
    *listed_assets* — the confirmed assets the last refresh listed (None = unknown).
    *clock* — a monotonic clock in seconds.
    """

    def __init__(self, node_assets: CountSource, listed_assets: CountSource,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._node_assets = node_assets
        self._listed_assets = listed_assets
        self._clock = clock
        self._last_probe_at: Optional[float] = None
        self._last_trigger_at: Optional[float] = None
        self._triggered_for: Optional[int] = None

    @classmethod
    def for_config(cls, load_config: Callable[[], Any]) -> GrowthWatch:
        """A watch over the configured verified graph, re-reading the config on
        every probe so a changed graph id or node URL is followed without a restart."""

        def node_assets() -> Optional[int]:
            config = load_config()
            client = DkgClient.for_config(config)
            totals = verified_download_totals(client, config.context_graph_id, timeout=PROBE_TIMEOUT_SECONDS)
            return totals.assets if totals is not None else None

        def listed_assets() -> Optional[int]:
            listed = (progress(load_config().context_graph_id) or {}).get("assets_total")
            return listed if isinstance(listed, int) else None

        return cls(node_assets, listed_assets)

    def check(self) -> bool:
        """True exactly when a refresh should start now. Probes at most every
        :data:`PROBE_EVERY_SECONDS`; between probes it answers False at once."""
        now = self._clock()
        if self._last_probe_at is not None and now - self._last_probe_at < PROBE_EVERY_SECONDS:
            return False
        self._last_probe_at = now
        held, listed = self._node_assets(), self._listed_assets()
        if held is None or listed is None or held <= listed:
            return False
        if self._triggered_for is not None and held <= self._triggered_for:
            return False   # this count already asked for its refresh
        if self._last_trigger_at is not None and now - self._last_trigger_at < MIN_TRIGGER_GAP_SECONDS:
            return False
        self._triggered_for, self._last_trigger_at = held, now
        return True
