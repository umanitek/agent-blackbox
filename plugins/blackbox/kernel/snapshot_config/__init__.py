"""Explicit trust configuration for the public core snapshot sync capability."""
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DKG_CORE_CHAIN_CACHE = "DKG_Core_chain_cache"
REGISTERED_BASE_CORES = "base-mainnet-registered-cores"


@dataclass(frozen=True)
class SnapshotSyncConfig:
    on_chain_id: str
    trusted_core_peers: tuple[str, ...]
    mode: str = "core-cache"
    source_policy: str | None = None


def snapshot_config(entry):
    raw = entry.get("snapshot_sync")
    if raw is None:
        return None  # Preserve existing profiles until the new daemon is installed.
    if not isinstance(raw, dict) or set(raw) - {"on_chain_id", "trusted_core_peers", "mode", "source_policy", DKG_CORE_CHAIN_CACHE}:
        raise ValueError("Invalid snapshot_sync configuration")
    enabled = raw.get(DKG_CORE_CHAIN_CACHE)
    if DKG_CORE_CHAIN_CACHE in raw and not isinstance(enabled, bool):
        raise ValueError("DKG_Core_chain_cache must be true or false")
    if enabled is False:
        if raw.get("source_policy") or raw.get("trusted_core_peers"):
            raise ValueError("Disabled DKG_Core_chain_cache conflicts with explicit snapshot trust")
        return None
    mode = raw.get("mode", "core-cache")
    graph_id = str(raw.get("on_chain_id", ""))
    peers = raw.get("trusted_core_peers", [] if enabled else None)
    policy = raw.get("source_policy")
    if enabled:
        if policy not in (None, DKG_CORE_CHAIN_CACHE):
            raise ValueError("DKG_Core_chain_cache conflicts with another source policy")
        policy = DKG_CORE_CHAIN_CACHE
    if (mode not in {"core-cache", "rpc-only"} or not graph_id.isascii()
            or not graph_id.isdecimal() or graph_id.startswith("0") or len(graph_id) > 78
            or int(graph_id) >= 2 ** 256 or not isinstance(peers, list)
            or policy not in (None, REGISTERED_BASE_CORES, DKG_CORE_CHAIN_CACHE)
            or (len(peers) != 0 if policy else not 1 <= len(peers) <= 4)
            or any(not isinstance(p, str) or not p or len(p) > 256 or p.strip() != p for p in peers)
            or len(set(peers)) != len(peers)):
        raise ValueError("snapshot_sync needs a positive on_chain_id, explicit trusted_core_peers or DKG_Core_chain_cache, and core-cache or rpc-only mode")
    return SnapshotSyncConfig(graph_id, tuple(peers), mode, policy)


#: Block errors this process has already logged (every hook loads the config).
_WARNED_ERRORS: set[str] = set()


def snapshot_fields(entry) -> dict:
    """The two ``BlackboxConfig`` fields for *entry*'s block, never raising.

    ``{"snapshot_sync": settings or None, "snapshot_sync_error": "" or why}``. An invalid
    block is set aside with its reason rather than raised: the config is loaded by every
    hook, so raising let every tool call through unchecked (KI-490). Sync refuses while the
    error is set — there is no automatic trust fallback. Code validating a block someone is
    about to save calls :func:`snapshot_config` and gets the ValueError.

    Usage::

        BlackboxConfig(mode=mode, **snapshot_fields(entry))
    """
    try:
        return {"snapshot_sync": snapshot_config(entry), "snapshot_sync_error": ""}
    except ValueError as exc:
        if str(exc) not in _WARNED_ERRORS:
            _WARNED_ERRORS.add(str(exc))
            logger.warning("blackbox: the snapshot_sync block in config.yaml is invalid (%s); protection "
                           "keeps running and sync is refused until it is corrected", exc)
        return {"snapshot_sync": None, "snapshot_sync_error": str(exc)}


def query_evidence(config, url, home):
    """Never transfer a profile's core-cache consent to another daemon or home."""
    from pathlib import Path
    settings = getattr(config, "snapshot_sync", None)
    if (settings is None or config.dkg_url.rstrip("/") != url
            or Path(config.dkg_home).expanduser().resolve() != Path(home).expanduser().resolve()):
        return None
    return config.context_graph_id, settings.mode


__all__ = ["DKG_CORE_CHAIN_CACHE", "REGISTERED_BASE_CORES", "SnapshotSyncConfig", "query_evidence", "snapshot_config"]
