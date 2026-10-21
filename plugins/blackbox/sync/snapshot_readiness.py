"""Read-only admission for a new snapshot default; never remove a protection tier."""
import time

from ..kernel import constants
from ..kernel.config import load_blackbox_config
from ..kernel.snapshot_config import DKG_CORE_CHAIN_CACHE
from ..ruleset import validate_config, LocalGraphClient
from .core_snapshot import PATH, SnapshotSyncClient, _matches_requested_scope, _registered_sources_valid

# A completed local job proves authenticated source selection, unlike advertised
# peer roles or a version string. Old completion records cannot enable a rollout.
SOURCE_PROOF_MAX_AGE_SECONDS = 60


def requested_profile(graph_id="14"):
    return {"detection_backend": "dkg", "snapshot_sync": {
        "on_chain_id": graph_id, "trusted_core_peers": [], "mode": "core-cache", DKG_CORE_CHAIN_CACHE: True}}


def candidate_config(entry, requested):
    return load_blackbox_config(entry={**entry, **requested})


def recent_verified_sources(job, cfg):
    settings = cfg.snapshot_sync
    payload = {"contextGraphId": cfg.context_graph_id, "onChainId": settings.on_chain_id,
               "trustedCorePeerIds": [], "mode": "core-cache", "sourcePolicy": DKG_CORE_CHAIN_CACHE}
    capabilities = job.get("capabilities")
    if (not isinstance(capabilities, dict) or not isinstance(capabilities.get("sourcePolicies"), list)
            or DKG_CORE_CHAIN_CACHE not in capabilities["sourcePolicies"]):
        return False
    if (not isinstance(job.get("id"), str) or not job["id"] or job.get("state") != "complete"
            or not _matches_requested_scope(job.get("request"), payload)):
        return False
    finished = job.get("finishedAt")
    now = time.time() * 1000
    if (type(finished) not in (int, float)
            or not now - SOURCE_PROOF_MAX_AGE_SECONDS * 1000 <= finished <= now):
        return False
    result = job.get("result")
    return (isinstance(result, dict) and result.get("mode") == "core-cache"
            and result.get("current") is True and result.get("completeAsOfSnapshot") is True
            and type(result.get("assets")) is int and result["assets"] > 0
            and type(result.get("committed")) is int and result["committed"] == result["assets"]
            and _registered_sources_valid(result, payload))


def defaults(entry, network="mainnet-base"):
    """Return a validated default or nothing. No sync, subscription or config write.

    Community-enabled profiles keep their existing reader until direct reads
    preserve its retention, reader budgets and curator semantics. A daemon with
    only capability advertisements is insufficient: source availability must
    have been proven by a recent, matching, completed authenticated local job.
    """
    if network != "mainnet-base":
        return {}
    requested = requested_profile()
    try:
        cfg = candidate_config(entry, requested)
        if cfg.context_graph_id != constants.DEFAULT_CONTEXT_GRAPH_ID:
            return {}
        if cfg.detection_backend != "dkg":
            return {}
        validate_config(cfg)
        job = SnapshotSyncClient(cfg).request("GET", PATH, timeout=3)
        if recent_verified_sources(job, cfg):
            queries = LocalGraphClient(cfg).request("GET", "/api/query/bounded")
            if (type(queries.get("version")) is int and queries["version"] == 1
                    and isinstance(queries.get("chainEvidenceModes"), list)
                    and "core-cache" in queries["chainEvidenceModes"]):
                return requested
    except (OSError, ValueError, RuntimeError):
        # Unknown readiness retains ordinary sync; explicit configured profiles
        # are handled by their own runtime checks and never silently downgraded.
        return {}
    return {}


def validate_requested_profile(entry, requested):
    try:
        validate_config(candidate_config(entry, requested))
    except RuntimeError as exc:
        raise ValueError(f"Snapshot profile unavailable: {exc}. Existing community and sync settings were not changed.") from exc
