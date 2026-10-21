"""Explicit trust configuration for the public core snapshot sync capability."""
from dataclasses import dataclass

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
    if entry.get("detection_backend", "legacy-cache") != "dkg":
        raise ValueError("snapshot_sync requires detection_backend: dkg")
    return SnapshotSyncConfig(graph_id, tuple(peers), mode, policy)
