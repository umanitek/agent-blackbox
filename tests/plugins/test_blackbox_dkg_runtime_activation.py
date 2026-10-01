"""Runtime-only activation across existing managed DKG syncs."""

import argparse
from dataclasses import replace
import json
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox


cli = load_blackbox("cli")
config = load_blackbox("config")
constants = load_blackbox("constants")
STREAM_ENV = "DKG_EXPERIMENTAL_EXACT_BATCH_STREAM"


@pytest.fixture
def installation(tmp_path, monkeypatch):
    home = tmp_path / "dkg"
    home.mkdir()
    binary = tmp_path / "cli.js"
    binary.write_text("// installed CLI fixture\n", encoding="utf-8")
    (home / "config.json").write_text(json.dumps({
        "syncOnConnectEnabled": True,
        "syncReconcilerEnabled": False,
        "vmReconcilerEnabled": True,
        "durableSyncEnabled": True,
        "syncGlobalMaxInflight": 1,
        "syncGlobalQueueLimit": 0,
        "syncSharedMemoryOnConnect": False,
    }) + "\n", encoding="utf-8")
    for name in ("identity.key", "rules-cache.json", "inventory.sqlite3"):
        (home / name).write_bytes(b"existing installation state")
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    monkeypatch.delenv(STREAM_ENV, raising=False)
    monkeypatch.setattr(cli, "_managed_dkg_node_executable", lambda _cfg: None)
    # Safety-profile capture is independently exercised at the real restart
    # boundary in test_blackbox_dkg_runtime_safety.py; this fixture isolates
    # the activation policy and never inspects or starts an actual process.
    monkeypatch.setattr(
        cli.dkg_runtime_safety, "prepare_restart_environment", lambda *_args: None
    )
    return config.BlackboxConfig(dkg_home=str(home), dkg_bin=str(binary))


def test_default_native_start_enables_streaming_without_persisting_it(installation):
    cfg = installation
    path = Path(cfg.dkg_home) / "config.json"
    before = path.read_bytes()

    assert cli._dkg_sync_environment(cfg)[STREAM_ENV] == "1"
    assert cli._set_persisted_dkg_steady_state(cfg) is False
    assert path.read_bytes() == before


@pytest.mark.parametrize("value", ["0", "1", ""])
def test_native_start_and_live_policy_preserve_explicit_flag(
    installation, monkeypatch, value
):
    monkeypatch.setenv(STREAM_ENV, value)
    assert cli._dkg_sync_environment(installation)[STREAM_ENV] == value
    assert cli._dkg_runtime_sync_settings(installation)[STREAM_ENV] == value


@pytest.mark.parametrize("selection", [
    {"context_graph_id": "operator-private-graph"},
    {"graph_peer_id": "operator-publisher"},
    {"context_graph_id": next(iter(constants.LEGACY_CONTEXT_GRAPH_IDS))},
])
@pytest.mark.parametrize("explicit", [None, "0", "1"])
def test_custom_and_legacy_paths_keep_existing_environment(
    installation, monkeypatch, selection, explicit
):
    cfg = replace(installation, **selection)
    if explicit is not None:
        monkeypatch.setenv(STREAM_ENV, explicit)
    env = cli._dkg_sync_environment(cfg)

    assert STREAM_ENV not in cli._dkg_runtime_sync_settings(cfg)
    if explicit is None:
        assert STREAM_ENV not in env
    else:
        assert env[STREAM_ENV] == explicit


@pytest.mark.parametrize(("explicit", "live", "expected_restarts"), [
    (None, None, 1),
    (None, "0", 1),
    (None, "1", 0),
    ("0", None, 0),
    ("0", "0", 0),
    ("0", "1", 1),
])
def test_managed_sync_adopts_runtime_once_then_reuses_worker(
    installation, monkeypatch, explicit, live, expected_restarts
):
    cfg = installation
    home = Path(cfg.dkg_home)
    preserved = {
        path: path.read_bytes() for path in home.iterdir() if path.is_file()
    }
    (home / "daemon.pid").write_text("4242\n", encoding="utf-8")
    if explicit is not None:
        monkeypatch.setenv(STREAM_ENV, explicit)
    live_env = dict(cli._DKG_NATIVE_SYNC_SETTINGS)
    if live is not None:
        live_env[STREAM_ENV] = live
    restarts = []
    observations = []

    class Process:
        def __init__(self, pid):
            assert pid == 4242

        def environ(self):
            return dict(live_env)

    def restart(_cfg):
        env = cli._dkg_sync_environment(_cfg)
        restarts.append(env)
        live_env.clear()
        live_env.update(env)

    def observe(_args):
        observations.append(True)
        cli.sync_state.write(
            "partial", context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id, phase="verified-rules-available",
            public_entries=1000, detection_ready=True,
            graph_complete=False, complete=False,
        )
        return 0

    monkeypatch.setattr(cli.psutil, "Process", Process)
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(cli, "_restart_managed_dkg", restart)
    monkeypatch.setattr(cli, "_cmd_sync_impl", observe)
    args = argparse.Namespace(wait=True, timeout=30, require_rules=True)

    assert cli._cmd_sync(args) == 0
    assert cli._cmd_sync(args) == 0
    assert len(restarts) == expected_restarts
    assert observations == [True, True]
    if restarts:
        assert restarts[0][STREAM_ENV] == (explicit or "1")
    assert all(path.read_bytes() == data for path, data in preserved.items())
    state = cli.sync_state.read_for_graph(cfg.context_graph_id)
    assert state["status"] == "partial"
    assert state["graph_complete"] is False
    assert state["complete"] is False
