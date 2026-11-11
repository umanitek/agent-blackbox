"""Read-only admission for a new snapshot default; never remove a protection tier."""
from ..kernel import constants
from ..kernel.config import load_blackbox_config, reads_graph_directly
from ..kernel.snapshot_config import DKG_CORE_CHAIN_CACHE, snapshot_config
from ..ruleset import validate_config, local_graph_url
from .core_snapshot import PATH, SnapshotSyncClient

def requested_profile(graph_id="14"):
    return {"snapshot_sync": {
        "on_chain_id": graph_id, "trusted_core_peers": [], "mode": "core-cache", DKG_CORE_CHAIN_CACHE: True}}


def candidate_config(entry, requested):
    candidate = {**entry, **requested}
    snapshot_config(candidate)   # a block being proposed must be valid: raises ValueError
    return load_blackbox_config(entry=candidate)


def defaults(entry, network="mainnet-base"):
    """Select the snapshot transport without changing the detection/protection model.

    The local capability admits an attempt, never proves a core or coverage.
    The owned first job authenticates registered cores and their scoped snapshot
    BEFORE admitting data. Missing/incompatible DKG keeps ordinary sync. An
    admitted job fails closed if no core qualifies; it never downgrades trust.
    Requiring a previous completed job here made first-install activation impossible.
    """
    if network != "mainnet-base":
        return {}
    requested = requested_profile()
    try:
        cfg = candidate_config(entry, requested)
        if (cfg.context_graph_id != constants.DEFAULT_CONTEXT_GRAPH_ID
                or cfg.graph_peer_id != constants.DEFAULT_GRAPH_PEER_ID):
            return {}
        local_graph_url(cfg.dkg_url)
        job = SnapshotSyncClient(cfg).request("GET", PATH, timeout=3)
        capabilities = job.get("capabilities", {})
        if (job.get("state") in {"idle", "complete", "failed"}
                and isinstance(capabilities, dict)
                and isinstance(capabilities.get("sourcePolicies"), list)
                and DKG_CORE_CHAIN_CACHE in capabilities["sourcePolicies"]):
            return requested
    except (OSError, ValueError, RuntimeError):
        return {}
    return {}


def validate_requested_profile(entry, requested):
    try:
        cfg = candidate_config(entry, requested)
        local_graph_url(cfg.dkg_url)
        if reads_graph_directly(cfg):
            validate_config(cfg)
    except RuntimeError as exc:
        raise ValueError(f"Snapshot profile unavailable: {exc}. Existing community and sync settings were not changed.") from exc
