"""Refreshing the compiled ruleset: fetch -> compile -> merge community tier -> cache.

Owns the in-memory generation (``_memory``, a :class:`RulesetCache`), the
refresh cycle (:func:`refresh`, background refresh,
tier restore on partial failure) and the read accessors :func:`get` and
:func:`peek`. The community tier is merged by :mod:`.community_tier` after the
verified build — the ruleset depends on community, never the reverse.

Usage: ``ruleset.get(cfg)`` (cached, refreshes in the background when stale) ·
``ruleset.refresh(cfg, force=True)`` · ``ruleset.peek(cfg)`` (never fetches).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, List, Optional
from ..kernel import constants
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient
from . import compiler
from . import disk_cache
from . import errors
from . import fetching
from . import partitions
from . import community_tier
from . import curator_tier
from .. import community
from . import locks
from .memory_cache import RulesetCache
from . import pulse_beat

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

def _cache_file_stamp() -> Optional[int]:
    try:
        return disk_cache._cache_path().stat().st_mtime_ns
    except OSError:
        return None


def _new_memory() -> RulesetCache:
    # Late-bound lambdas: tests (and nothing else) patch these module names.
    return RulesetCache(stamp=lambda: _cache_file_stamp(), load=lambda: disk_cache._read_cache())


_memory = _new_memory()
_refreshing = False
_refreshing_lock = threading.Lock()  # guards the spawn-one-background-refresh flag


def _matches_context_graph(rs: Optional[compiler.Ruleset], context_graph_id: str) -> bool:
    """Return whether a cache generation belongs to the requested graph.

    Cache files written before graph identity was persisted are accepted only
    for the built-in release graph. They cannot safely be attributed to an
    explicitly configured custom graph.
    """
    if rs is None:
        return False
    cached_graph = str(rs.context_graph_id or "")
    if cached_graph:
        return cached_graph == context_graph_id
    return context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID


def _latest_cached_ruleset(context_graph_id: str = "") -> Optional[compiler.Ruleset]:
    """Return the matching memory/disk generation, reloading replacements."""
    cached = _memory.current()
    if context_graph_id and not _matches_context_graph(cached, context_graph_id):
        return None
    return cached


_EMPTY_RULESET_RETRY_S = 30.0
#: While the verified graph is only partly compiled, refresh again this soon so
#: the rules reach the whole graph in minutes, not hours (KI-288); long enough
#: for the store's post-deadline recovery window to clear.
_CATCHING_UP_RETRY_S = 120.0
_NONEMPTY_REFRESH_MIN_S = 15 * 60.0


def refresh(
    config: Optional[BlackboxConfig] = None,
    client: Optional[DkgClient] = None,
    *,
    wait_for_lock: bool = True,
    force_query: bool = False,
) -> compiler.Ruleset:
    """Query the node, rebuild the ruleset, and persist it. Fail-open.

    Reads only the verified public graph (VM), fully paginated (no cap). If its
    query fails, the last-good public rules are preserved. On total
    failure, returns the last-good cache or an empty ruleset. ``force_query``
    raises :class:`RulesetRefreshUnavailable` unless it can acquire the
    serialization lock and read a non-empty VM snapshot, allowing
    completion-barrier callers to fail closed. ``force_query`` is reserved for
    callers that have crossed a DKG completion barrier and must not adopt a
    generation started before that barrier.
    """
    config = config or load_blackbox_config()
    if config.detection_backend == "dkg":
        from ..graph_read.view import GraphView
        result = GraphView(config)
        result.counts()  # live capability/readiness check; no rule extraction
        return result
    context_graph_id = config.context_graph_id
    initial_stamp = _cache_file_stamp()
    with locks._ruleset_refresh_lock(blocking=wait_for_lock) as acquired:
        if not acquired:
            if force_query:
                raise errors.RulesetRefreshLockUnavailable(
                    "post-barrier ruleset refresh lock is unavailable"
                )
            return _latest_cached_ruleset(context_graph_id) or compiler.Ruleset(
                context_graph_id=context_graph_id
            )
        # If another process completed while this caller waited, its atomic
        # replacement is the requested fresh generation. Reuse it instead of
        # immediately issuing the same large query sequence again.
        if not force_query and _cache_file_stamp() != initial_stamp:
            latest = _latest_cached_ruleset(context_graph_id)
            if latest is not None:
                return latest
        return _refresh_unlocked(config, client, require_complete=force_query)


def _refresh_unlocked(
    config: Optional[BlackboxConfig] = None,
    client: Optional[DkgClient] = None,
    *,
    require_complete: bool = False,
) -> compiler.Ruleset:
    """Refresh while the caller holds :func:`_ruleset_refresh_lock`."""
    config = config or load_blackbox_config()
    if config.detection_backend == "dkg":
        return refresh(config)  # internal/background callers also cannot export
    context_graph_id = config.context_graph_id
    client = client or DkgClient(url=config.dkg_url, dkg_home=config.dkg_home)
    tiers = ((constants.VIEW_VERIFIABLE_MEMORY, "public"),)
    fetched = {tier: fetching.fetch_tier(client, config.context_graph_id, view) for view, tier in tiers}

    # An entirely empty store gets an early cache-expiry below. Subscription,
    # admission, and catch-up are DKG daemon responsibilities; a cache read must
    # never restart network recovery.
    empty_success = all(rows == [] for rows in fetched.values())
    failed_tiers = [tier for tier, rows in fetched.items() if rows is None]

    if require_complete:
        if failed_tiers:
            raise errors.RulesetRefreshIncomplete(
                "post-barrier VM query failed for "
                + ", ".join(sorted(failed_tiers))
            )
        if empty_success:
            raise errors.RulesetRefreshIncomplete(
                "post-barrier VM query returned an empty snapshot"
            )

    if empty_success:
        # Snapshot replacement is atomic from the user's perspective. A
        # transient empty query (or a concurrent refresh racing catch-up)
        # must never erase an already verified, enforceable ruleset.
        disk_prior = disk_cache._read_cache()
        candidates = [
            item
            for item in (_memory.memory_only(), disk_prior)
            if _matches_context_graph(item, context_graph_id)
        ]
        prior = max(candidates, key=lambda item: item.source_count("public"), default=None)
        if prior is not None and prior.source_count("public") > 0:
            return _reuse_generation(prior, context_graph_id, client, config)

    if all(rows is None for rows in fetched.values()):
        # Every tier failed — keep the last-good ruleset instead of emptying.
        existing = _latest_cached_ruleset(context_graph_id)
        if existing is not None:
            return _reuse_generation(existing, context_graph_id, client, config)

    rows: List[Any] = []
    for tier, view_rows in fetched.items():
        if view_rows is None:  # a failed tier (fail-open handled below)
            continue
        rows.extend((row, tier) for row in view_rows)
    rs = compiler.build_from_rows(rows)
    rs.context_graph_id = context_graph_id
    _apply_overlays(rs, client, config)
    _schedule_next_refresh(rs, config, empty_success)

    errored = failed_tiers
    if errored:
        prior = _latest_cached_ruleset(context_graph_id)
        if prior is not None:
            _restore_tiers(rs, prior, errored)

    disk_cache._write_cache(rs)
    _memory.store(rs)
    return rs


def _reuse_generation(rs: compiler.Ruleset, context_graph_id: str, client: Optional[DkgClient],
                      config: BlackboxConfig) -> compiler.Ruleset:
    """Keep *rs* (last-good verified tier) as the new generation: re-stamp it,
    refresh its community tier (it must refresh on every path — R0 tri-state),
    write it to disk and memory."""
    rs.context_graph_id = context_graph_id
    rs.synced_at = time.time()
    _schedule_next_refresh(rs, config, False)   # a deferred read while catching up retries soon
    _apply_overlays(rs, client, config, reused=True)
    disk_cache._write_cache(rs)
    _memory.store(rs)
    return rs


def _apply_overlays(rs: compiler.Ruleset, client: Optional[DkgClient], config: BlackboxConfig, *,
                    reused: bool = False) -> None:
    """The tiers layered on top of the verified build, on EVERY refresh path.

    First the curator tier (Refine R2): verified rules the curator revoked are
    withdrawn — always, with or without a community graph, because a
    revocation reduces enforcement. Then the community tier (B5), applied
    after the verified build so public
    rules already occupy their keys (public-beats-community precedence is
    then structural). *reused* = *rs* is a last-good generation being kept
    (its community tier is re-applied in place); otherwise the previous cached
    generation supplies first-seen history and last-good. Entirely fail-open:
    a community problem never degrades the verified ruleset.
    """
    if client is None:
        return
    curator_tier.apply_curator_tier(rs, client, config)
    if not config.community_graph_id:
        return
    # KI-208: record what the graph looks like BEFORE this read, so anything that
    # lands during or after it shows up as a change to the next pulse of any process.
    rs.community_fingerprint = community.community_fingerprint(client, config) or ""
    if reused:
        community_tier.reapply_community_tier(rs, client, config)
    else:
        community_tier.apply_community_tier(rs, client, config, _latest_cached_ruleset(config.context_graph_id))
    _publish_digests(client, config)
    _retry_shares(client, config)
    _keep_reports_alive(client, config)
    _record_shadow_metrics(rs, config)
    community.PULSE.reset()   # a full read just happened; the next pulse starts from it


def _record_shadow_metrics(rs: compiler.Ruleset, config: BlackboxConfig) -> None:
    """R15: in the shadow phase every refresh logs the §12 numbers it computed. Fail-open."""
    if not getattr(config, "community_shadow", False):
        return
    try:
        community.shadow.write_snapshot(community.shadow.build_snapshot(rs, time.time()))
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.debug("blackbox: shadow metrics skipped this refresh: %s", exc)


def _keep_reports_alive(client: DkgClient, config: BlackboxConfig) -> None:
    """R5: the refresh cycle is the publish step for keep-alive — this node's
    own live reports get this epoch's copy here (when sharing is on). Fail-open."""
    try:
        community.publish_due_copies(client, config)
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.warning("blackbox: keep-alive copies not published this refresh: %s", exc)


def _retry_shares(client: DkgClient, config: BlackboxConfig) -> None:
    """R16: every periodic beat also retries refused community shares. Fail-open."""
    try:
        community.retry_due_shares(client, config)
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.debug("blackbox: share retry skipped this beat: %s", exc)


def _publish_digests(client: DkgClient, config: BlackboxConfig) -> None:
    """R2b: the refresh cycle is the one periodic beat, so a completed week's
    sighting digest leaves here (when sharing is on). Fail-open."""
    try:
        community.publish_due_digests(client, config)
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.warning("blackbox: sighting digest not published this refresh: %s", exc)


def _restore_tiers(rs: compiler.Ruleset, prior: compiler.Ruleset, tiers: List[str]) -> None:
    """Re-add *prior* rules from the given (errored) *tiers* into *rs*.

    Only fills gaps: a rule already present from a freshly-fetched tier wins,
    and public still beats community for a shared dependency key — mirroring
    :func:`build_from_rows` precedence.
    """
    keep = set(tiers)
    graph_seen = {(item.get("source"), item.get("identifier")) for item in rs.graph_threats}
    for item in prior.graph_threats:
        key = (item.get("source"), item.get("identifier"))
        if item.get("source") in keep and key not in graph_seen:
            graph_seen.add(key)
            rs.graph_threats.append(item)
    for attr in ("injection", "escalation", "fileaccess", "skill"):
        seen = {r.get("identifier") for r in getattr(rs, attr)}
        for rule in getattr(prior, attr):
            if rule.get("source") in keep and rule.get("identifier") not in seen:
                getattr(rs, attr).append(rule)
    for attr in ("dependency", "ioc"):
        target = getattr(rs, attr)
        for key, rule in getattr(prior, attr).items():
            if rule.get("source") not in keep:
                continue
            existing = target.get(key)
            if existing is None or (existing.get("source") == "community" and rule.get("source") == "public"):
                target[key] = rule
    rs._graph_entries_cache.clear()


def _background_refresh(config: BlackboxConfig) -> None:
    global _refreshing
    try:
        refresh(config, wait_for_lock=False)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: background refresh failed: %s", exc)
    finally:
        _refreshing = False


def _schedule_next_refresh(rs: compiler.Ruleset, config: BlackboxConfig, empty_success: bool) -> None:
    """Set ``rs.refresh_due_at`` when the next refresh should come before a full interval.

    A fresh node's subscribe/catch-up is async. Do not cache "0 rules" as
    fresh for the full sync interval; retry soon so the dashboard updates
    shortly after VM lands locally. Likewise, while the last refresh compiled
    only part of the verified graph, come back in :data:`_CATCHING_UP_RETRY_S`
    rather than an hour (KI-288). ``synced_at`` stays the real compile time (KI-304).
    """
    if empty_success:
        retry_after = _EMPTY_RULESET_RETRY_S
    elif partitions.catching_up(rs.context_graph_id):
        retry_after = _CATCHING_UP_RETRY_S
    else:
        rs.refresh_due_at = 0.0
        return
    interval = max(1.0, float(config.sync_interval or 1))
    rs.refresh_due_at = time.time() + min(retry_after, interval)


def get(config: Optional[BlackboxConfig] = None) -> compiler.Ruleset:
    """Return the cached ruleset, lazily refreshing in the background if stale.

    Never blocks on the network: a stale cache is returned immediately while a
    single background thread refreshes it for the next call.
    """
    global _refreshing
    config = config or load_blackbox_config()
    if config.detection_backend == "dkg":
        from ..graph_read.view import GraphView
        return GraphView(config)
    cached = _latest_cached_ruleset(config.context_graph_id)
    if cached is None:
        disk = disk_cache._read_cache()
        cached = (
            disk
            if _matches_context_graph(disk, config.context_graph_id)
            else compiler.Ruleset(context_graph_id=config.context_graph_id)
        )
        _memory.store(cached)
    refresh_after = max(1.0, float(config.sync_interval or 1))
    if cached.source_count("public") > 0:
        refresh_after = max(refresh_after, _NONEMPTY_REFRESH_MIN_S)
    due = cached.refresh_due(refresh_after)
    # Atomic check-and-set under the lock so two callers can't both spawn.
    should_spawn = False
    with _refreshing_lock:
        if time.time() > due and not _refreshing:
            _refreshing = True
            should_spawn = True
    if should_spawn:
        try:
            threading.Thread(
                target=_background_refresh, args=(config,), name="blackbox-ruleset", daemon=True
            ).start()
        except Exception:  # pragma: no cover
            with _refreshing_lock:
                _refreshing = False
    else:
        pulse_beat.pulse(config)   # R16: the cheap beat between refreshes (never blocks)
    return cached


def peek(config: Optional[BlackboxConfig] = None) -> compiler.Ruleset:
    """Return the last cached ruleset without starting a node refresh.

    The dashboard has one dedicated refresh worker. Request handlers and the
    dashboard's catch-up watcher use this read-only path so a large initial DKG
    transfer cannot accidentally fan out additional Blazegraph queries.
    """
    config = config or load_blackbox_config()
    if config.detection_backend == "dkg":
        from ..graph_read.view import GraphView
        return GraphView(config)
    cached = _latest_cached_ruleset(config.context_graph_id)
    if cached is None:
        disk = disk_cache._read_cache()
        cached = (
            disk
            if _matches_context_graph(disk, config.context_graph_id)
            else compiler.Ruleset(context_graph_id=config.context_graph_id)
        )
        _memory.store(cached)
    return cached
