"""The community pulse beat (R16): between full refreshes, retry refused shares
and re-apply the community tier when the community graph changed.

The probe itself (``community.PULSE``) only answers "did the graph change?";
this module owns the BEAT — spawning at most one background thread, at most
every ``config.community_poll_interval`` seconds (0 disables) — and the
write-through onto the cached generation (disk + memory, under the refresh
lock, so every process picks it up on its next call). Called from
``refresh_cycle.get`` (every hook) and by the dashboard's health poll.

Usage: ``ruleset.pulse(cfg)`` → True when a probe was started.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from .. import community
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient
from . import community_tier, disk_cache, locks

logger = logging.getLogger(__name__)

_pulsing = False
_pulsing_since = 0.0
_pulsing_lock = threading.Lock()  # guards the spawn-one-background-pulse flag
#: A beat older than this is presumed wedged (a node call that never returned):
#: the next due pulse may start a fresh beat instead of waiting forever.
STUCK_BEAT_SECONDS = 300.0


def pulse(config: Optional[BlackboxConfig] = None) -> bool:
    """Start the beat if it is due; never blocks; returns whether a probe started."""
    global _pulsing, _pulsing_since
    config = config or load_blackbox_config()
    if getattr(config, 'detection_backend', 'legacy-cache') == "dkg":
        return False  # direct reads never create or update the exported ruleset
    interval = float(getattr(config, "community_poll_interval", 0) or 0)
    if interval <= 0 or not config.community_graph_id or not community.PULSE.due(interval):
        return False
    with _pulsing_lock:
        if _pulsing and time.time() - _pulsing_since < STUCK_BEAT_SECONDS:
            return False
        if _pulsing:
            logger.warning("blackbox: a community pulse beat has run for over %d s — starting a fresh one", int(STUCK_BEAT_SECONDS))
        _pulsing = True
        _pulsing_since = time.time()
    try:
        threading.Thread(target=_background_pulse, args=(config,), name="blackbox-pulse", daemon=True).start()
    except Exception:  # pragma: no cover
        with _pulsing_lock:
            _pulsing = False
        return False
    return True


def _background_pulse(config: BlackboxConfig) -> None:
    global _pulsing
    try:
        from . import refresh_cycle   # lazy: refresh_cycle imports this module

        client = DkgClient(url=config.dkg_url, dkg_home=config.dkg_home)
        # KI-216 / FIX-0039: the beat is the one path that ALWAYS runs on a node
        # (the heavy refresh fails outright on a node without the verified graph),
        # so membership — dial the owner, subscribe — lives here too. Membership
        # rate-limits itself; a confirmed subscription costs nothing per beat.
        community.ensure_community_subscription(client, config)
        refresh_cycle._retry_shares(client, config)
        cached = refresh_cycle.peek(config)
        # KI-208: a process with no probe yet compares against the fingerprint the
        # cached tier was applied at, so what arrived while nothing was beating is a change.
        changed = community.PULSE.changed(client, config, cached.community_fingerprint)
        # A process that just started (or a node whose first full refresh is an hour
        # away) baselines on reports that are ALREADY there: apply them once now
        # when the cached generation holds no community tier yet (bench finding
        # 2026-10-02: A's report never became matchable on B until a full refresh).
        empty_tier = not cached.community
        if changed or (community.PULSE.baselined_now and empty_tier and community.PULSE.report_count > 0):
            _reapply_community(config, client)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: community pulse failed: %s", exc)
    finally:
        with _pulsing_lock:
            _pulsing = False


def _reapply_community(config: BlackboxConfig, client: DkgClient) -> None:
    """Re-read the community tier onto the cached generation and write it
    through (disk + memory), so every process picks it up on its next call.
    Skipped when a full refresh holds the lock — it will read everything."""
    from . import refresh_cycle   # lazy: refresh_cycle imports this module

    with locks._ruleset_refresh_lock(blocking=False) as held:
        if not held:
            return
        rs = refresh_cycle.peek(config)
        community_tier.reapply_community_tier(rs, client, config)
        rs.community_fingerprint = community.PULSE.last_fingerprint   # KI-208: the baseline travels with the tier
        disk_cache._write_cache(rs)
        refresh_cycle._memory.store(rs)
        logger.info("blackbox: community tier re-applied on pulse (%d community rule(s))", len(rs.community))
