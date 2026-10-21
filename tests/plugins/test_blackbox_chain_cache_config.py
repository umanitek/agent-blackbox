"""The clear cache option selects only the daemon's authenticated policy."""
import argparse

import pytest
from _blackbox_loader import load_blackbox

settings = load_blackbox("kernel.snapshot_config")
profile = load_blackbox("setup.sync_profile")
config = load_blackbox("kernel.config")


def parse(**overrides):
    return settings.snapshot_config({"detection_backend": "dkg", "snapshot_sync": {
        "on_chain_id": "25", "DKG_Core_chain_cache": True, **overrides}})


def test_cache_option_selects_registered_policy_without_explicit_peers():
    result = parse()
    assert result.source_policy == "DKG_Core_chain_cache"
    assert result.trusted_core_peers == ()
    assert result.on_chain_id == "25"
    assert parse(DKG_Core_chain_cache=False) is None
    assert parse(mode="rpc-only").mode == "rpc-only"


@pytest.mark.parametrize("bad", ["true", 1, "false", {}, [], None])
def test_cache_option_requires_a_boolean(bad):
    with pytest.raises(ValueError):
        parse(DKG_Core_chain_cache=bad)


@pytest.mark.parametrize("override", [{"trusted_core_peers": ["peer"]},
    {"source_policy": "base-mainnet-registered-cores"},
    {"DKG_Core_chain_cache": False, "trusted_core_peers": ["peer"]}])
def test_conflicting_trust_scopes_are_refused(override):
    with pytest.raises(ValueError):
        parse(**override)


@pytest.mark.parametrize("network", ["mainnet-gnosis", "testnet"])
def test_other_networks_require_their_own_graph_id(tmp_path, monkeypatch, network):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_DKG_NETWORK", network)
    # This test selects an explicit public-only profile; community protection
    # is validated separately and must never be removed by setup.
    profile.yaml_files.dump_yaml(tmp_path / "config.yaml",
        {"plugins": {"entries": {"blackbox": {"community_graph_id": ""}}}})
    with pytest.raises(ValueError, match="snapshot-graph-id"):
        profile.configure(argparse.Namespace(dkg_core_chain_cache=True))
    profile.configure(argparse.Namespace(dkg_core_chain_cache=True, snapshot_graph_id="25"))
    result = config.load_blackbox_config().snapshot_sync
    assert result.source_policy == "DKG_Core_chain_cache" and result.on_chain_id == "25"
