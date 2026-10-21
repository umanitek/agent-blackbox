"""Admit compatible fresh defaults and preserve existing trust and protection settings."""
import os
from hermes_cli.config import require_readable_config_before_write
from ..kernel import constants, yaml_files
from ..sync import snapshot_defaults, validate_snapshot_profile
from ..kernel.snapshot_config import DKG_CORE_CHAIN_CACHE, REGISTERED_BASE_CORES, snapshot_config


def configure(args):
    graph_id = getattr(args, "snapshot_graph_id", None)
    peers = getattr(args, "trusted_core_peer", None)
    registered = getattr(args, "registered_cores", False)
    cache = getattr(args, "dkg_core_chain_cache", False)
    explicit = graph_id is not None or bool(peers) or registered or cache
    path, data, target = _entry()
    if not explicit:
        # Re-running setup must not migrate an existing graph or trust mode.
        if any(key in target for key in ("context_graph_id", "detection_backend", "snapshot_sync", "dkg_home")):
            return
        if (os.environ.get("BLACKBOX_DKG_NETWORK", "mainnet-base") != "mainnet-base"
                or os.environ.get("BLACKBOX_CONTEXT_GRAPH_ID", constants.DEFAULT_CONTEXT_GRAPH_ID)
                != constants.DEFAULT_CONTEXT_GRAPH_ID):
            return
        requested = snapshot_defaults(target, os.environ.get("BLACKBOX_DKG_NETWORK", "mainnet-base"))
        if requested:
            target.update(requested)
            yaml_files.dump_yaml(path, data)
        return
    if (registered or cache) and peers or (registered and cache):
        raise ValueError("Choose registered cores or explicit peers, not both")
    if (registered or cache) and graph_id is None:
        if (target.get("context_graph_id", constants.DEFAULT_CONTEXT_GRAPH_ID) != constants.DEFAULT_CONTEXT_GRAPH_ID
                or os.environ.get("BLACKBOX_DKG_NETWORK", "mainnet-base") != "mainnet-base"):
            raise ValueError("A custom graph requires --snapshot-graph-id")
        graph_id = "14"
    requested = {"detection_backend": "dkg", "snapshot_sync": {
        "on_chain_id": graph_id or "", "trusted_core_peers": peers or [], "mode": "core-cache",
        **({DKG_CORE_CHAIN_CACHE: True} if cache else {"source_policy": REGISTERED_BASE_CORES} if registered else {})}}
    snapshot_config(requested)
    existing = target.get("snapshot_sync")
    if existing is not None and existing != requested["snapshot_sync"]:
        raise ValueError("Existing snapshot trust differs; use a fresh profile for a different trust scope")
    validate_snapshot_profile(target, requested)
    target.update(requested)
    yaml_files.dump_yaml(path, data)
    print("Lower RPC usage by using the DKG Core chain cache: chain statements come from registered cores; "
          "asset identity and content roots are still verified. No automatic trust fallback.")


def _entry():
    path = constants.hermes_home() / "config.yaml"
    if yaml_files.yaml is None:
        raise ValueError("YAML support is required to configure snapshot sync")
    if path.is_symlink():
        raise ValueError("Configure the snapshot profile in the linked config file explicitly")
    try:
        data = require_readable_config_before_write(path)
    except Exception as exc:
        raise ValueError("Existing config.yaml could not be read; it was not changed") from exc
    target = data
    for key in ("plugins", "entries", "blackbox"):
        target = target.setdefault(key, {})
        if not isinstance(target, dict):
            raise ValueError("Existing Blackbox configuration must be a mapping")
    return path, data, target
