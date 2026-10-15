"""Explicit trust configuration for the public core snapshot sync capability."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SnapshotSyncConfig:
    on_chain_id: str
    trusted_core_peers: tuple[str, ...]
    mode: str = "core-cache"


def snapshot_config(entry):
    raw = entry.get("snapshot_sync")
    if raw is None:
        return None  # Preserve existing profiles until the new daemon is installed.
    if not isinstance(raw, dict) or set(raw) - {"on_chain_id", "trusted_core_peers", "mode"}:
        raise ValueError("Invalid snapshot_sync configuration")
    mode = raw.get("mode", "core-cache")
    graph_id = str(raw.get("on_chain_id", ""))
    peers = raw.get("trusted_core_peers")
    if (mode not in {"core-cache", "rpc-only"} or not graph_id.isascii()
            or not graph_id.isdecimal() or graph_id.startswith("0") or len(graph_id) > 78
            or int(graph_id) >= 2 ** 256 or not isinstance(peers, list)
            or not 1 <= len(peers) <= 4
            or any(not isinstance(p, str) or not p or len(p) > 256 or p.strip() != p for p in peers)
            or len(set(peers)) != len(peers)):
        raise ValueError("snapshot_sync needs a positive on_chain_id, one to four trusted_core_peers, and core-cache or rpc-only mode")
    if entry.get("detection_backend", "legacy-cache") != "dkg":
        raise ValueError("snapshot_sync requires detection_backend: dkg")
    return SnapshotSyncConfig(graph_id, tuple(peers), mode)
