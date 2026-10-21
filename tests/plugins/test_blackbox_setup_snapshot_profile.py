"""Setup preserves explicit snapshot trust and unrelated profile settings."""
import argparse
import subprocess

import pytest
from _blackbox_loader import load_blackbox

setup = load_blackbox("setup")
profile = load_blackbox("setup.sync_profile")
yaml_files = load_blackbox("kernel.yaml_files")
config = load_blackbox("kernel.config")


def args(**overrides):
    return argparse.Namespace(store="oxigraph", snapshot_graph_id="14", trusted_core_peer=["configured-core"], **overrides)


def test_setup_writes_explicit_snapshot_scope_before_install_without_losing_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    yaml_files.dump_yaml(path, {"model": "kept", "plugins": {"entries": {"blackbox": {"mode": "audit", "report": False, "community_graph_id": ""}}}})
    monkeypatch.setattr(setup, "_hermes_bin", lambda: "hermes")
    def install(command, **kwargs):
        cfg = config.load_blackbox_config()
        assert cfg.snapshot_sync.on_chain_id == "14"
        assert cfg.snapshot_sync.trusted_core_peers == ("configured-core",)
        assert cfg.snapshot_sync.mode == "core-cache" and cfg.detection_backend == "dkg"
        assert not cfg.report and cfg.mode == "audit"
        assert kwargs["env"]["BLACKBOX_DKG_PACKAGE"] == setup.DKG_PACKAGE
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(setup.subprocess, "run", install)
    assert setup.cmd_setup(args()) == 0
    assert yaml_files.load_yaml(path)["model"] == "kept"
    before = path.read_bytes()
    profile.configure(argparse.Namespace())  # ordinary upgrades preserve the choice
    assert path.read_bytes() == before


@pytest.mark.parametrize("graph_id,peers", [("14", None), (None, ["core"]), ("0", ["core"]), ("14", ["core", "core"])])
def test_incomplete_or_invalid_scope_does_not_touch_profile(tmp_path, monkeypatch, graph_id, peers):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with pytest.raises(ValueError):
        profile.configure(argparse.Namespace(snapshot_graph_id=graph_id, trusted_core_peer=peers))
    assert not (tmp_path / "config.yaml").exists()


def test_setup_refuses_silent_trust_replacement(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": {"community_graph_id": ""}}}})
    profile.configure(args())
    before = path.read_bytes()
    with pytest.raises(ValueError, match="fresh profile"):
        profile.configure(argparse.Namespace(snapshot_graph_id="14", trusted_core_peer=["another-core"]))
    assert path.read_bytes() == before


def test_fresh_community_profile_keeps_ordinary_sync_and_existing_profiles_stay_explicit(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("BLACKBOX_DKG_NETWORK", raising=False)
    monkeypatch.delenv("BLACKBOX_CONTEXT_GRAPH_ID", raising=False)
    profile.configure(argparse.Namespace())
    cfg = config.load_blackbox_config()
    assert cfg.snapshot_sync is None and cfg.community_graph_id
    assert cfg.detection_backend == "legacy-cache"
    path = tmp_path / "config.yaml"
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": {
        "detection_backend": "legacy-cache", "context_graph_id": "custom/graph"}}}})
    before = path.read_bytes()
    profile.configure(argparse.Namespace())
    assert path.read_bytes() == before


@pytest.mark.parametrize("override", ["network", "graph"])
def test_custom_network_or_graph_gets_no_implicit_trust(tmp_path, monkeypatch, override):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_DKG_NETWORK" if override == "network" else "BLACKBOX_CONTEXT_GRAPH_ID",
                       "mainnet-gnosis" if override == "network" else "custom/graph")
    profile.configure(argparse.Namespace())
    assert not (tmp_path / "config.yaml").exists()


def test_registered_policy_cannot_mix_in_explicit_peers_or_guess_custom_graph_id(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with pytest.raises(ValueError):
        profile.configure(args(registered_cores=True))
    path = tmp_path / "config.yaml"
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": {"context_graph_id": "custom/graph"}}}})
    before = path.read_bytes()
    with pytest.raises(ValueError, match="snapshot-graph-id"):
        profile.configure(argparse.Namespace(registered_cores=True))
    assert path.read_bytes() == before


@pytest.mark.parametrize("contents", ["plugins: [", "- one\n- two\n", "an invalid scalar\n"])
def test_setup_keeps_unparseable_or_non_mapping_config_unchanged(tmp_path, monkeypatch, contents):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    path.write_text(contents, encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="could not be read"):
        profile.configure(args())
    assert path.read_bytes() == before
