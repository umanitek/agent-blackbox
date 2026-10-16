"""Managed-DKG-node lifecycle during ``blackbox sync`` (KI-059 / KI-065).

Regression guards for the hourly node restart: the sync used to compare only
the worker's LAUNCH environment against the steady sync settings, so every
systemd-managed node (launched without those variables, configured through
``config.json``) looked stale and was restarted behind systemd's back on every
hourly sync — which then aborted that same sync on a dead node API.
"""

import argparse
import json

import pytest
from _blackbox_loader import load_blackbox

config_mod = load_blackbox("kernel.config")
cli_mod = load_blackbox("cli")
managed_node = load_blackbox("sync.managed_node")
sync_command = load_blackbox("sync.command")

_STEADY_CONFIG = {
    "syncOnConnectEnabled": True,
    "syncReconcilerEnabled": True,
    "durableSyncEnabled": True,
    "syncGlobalMaxInflight": 1,
    "syncGlobalQueueLimit": 4,
}


@pytest.fixture
def dkg_home(tmp_path, monkeypatch):
    """A DKG home with a live-worker pid file and steady persisted config.

    "Live" is stated, not assumed: node_process only trusts daemon.pid when it
    names a live daemon of this installation (KI-312), so pid 4242 is declared one.
    """
    (tmp_path / "daemon.pid").write_text("4242", encoding="utf-8")
    monkeypatch.setattr(managed_node.node_process, "is_managed_daemon", lambda _cfg, pid: pid == 4242)
    (tmp_path / "config.json").write_text(json.dumps(_STEADY_CONFIG), encoding="utf-8")
    return tmp_path


def _worker_with_env(monkeypatch, environ):
    class Process:
        def __init__(self, pid):
            assert pid == 4242

        def environ(self):
            return dict(environ)

    monkeypatch.setattr(managed_node.psutil, "Process", Process)


def test_service_launched_worker_without_env_overrides_is_in_steady_mode(dkg_home, monkeypatch):
    _worker_with_env(monkeypatch, {"PATH": "/usr/bin"})
    cfg = config_mod.BlackboxConfig(dkg_home=str(dkg_home))

    assert managed_node._managed_dkg_sync_mode_matches(cfg, managed_node._DKG_STEADY_SYNC_SETTINGS)


def test_stale_env_override_still_forces_restart_over_steady_config(dkg_home, monkeypatch):
    _worker_with_env(monkeypatch, {"DKG_SYNC_RECONCILER_ENABLED": "0"})
    cfg = config_mod.BlackboxConfig(dkg_home=str(dkg_home))

    assert not managed_node._managed_dkg_sync_mode_matches(cfg, managed_node._DKG_STEADY_SYNC_SETTINGS)


def test_stale_persisted_config_without_env_forces_restart(dkg_home, monkeypatch):
    stale = {**_STEADY_CONFIG, "syncReconcilerEnabled": False}
    (dkg_home / "config.json").write_text(json.dumps(stale), encoding="utf-8")
    _worker_with_env(monkeypatch, {})
    cfg = config_mod.BlackboxConfig(dkg_home=str(dkg_home))

    assert not managed_node._managed_dkg_sync_mode_matches(cfg, managed_node._DKG_STEADY_SYNC_SETTINGS)


def test_systemd_unit_is_read_from_process_cgroup(tmp_path):
    (tmp_path / "4242").mkdir()
    (tmp_path / "4242" / "cgroup").write_text(
        "0::/system.slice/blackbox-dkg.service\n", encoding="utf-8"
    )

    assert managed_node._systemd_unit_of(4242, proc_root=tmp_path) == "blackbox-dkg.service"


def test_detached_process_has_no_systemd_unit(tmp_path):
    (tmp_path / "4242").mkdir()
    (tmp_path / "4242" / "cgroup").write_text("0::/user.slice/session-3.scope\n", encoding="utf-8")

    assert managed_node._systemd_unit_of(4242, proc_root=tmp_path) is None
    assert managed_node._systemd_unit_of(9999, proc_root=tmp_path) is None


def test_service_managed_node_is_restarted_through_systemd(dkg_home, monkeypatch):
    commands = []

    class Client:
        def __init__(self, **_kwargs):
            pass

        def status(self, **_kwargs):
            return {"status": "ok"}

    def run(command, **_kwargs):
        commands.append(command)
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(managed_node, "_systemd_unit_of", lambda _pid: "blackbox-dkg.service")
    monkeypatch.setattr(managed_node, "_dkg_sync_environment", lambda _cfg: {})
    monkeypatch.setattr(managed_node.subprocess, "run", run)
    monkeypatch.setattr(sync_command, "DkgClient", Client)
    monkeypatch.setattr(managed_node, "DkgClient", Client)
    cfg = config_mod.BlackboxConfig(dkg_home=str(dkg_home), dkg_bin=str(dkg_home / "dkg"))

    managed_node._restart_managed_dkg(cfg)

    assert commands == [["systemctl", "restart", "blackbox-dkg.service"]]


def test_failed_systemd_restart_raises_with_detail(dkg_home, monkeypatch):
    monkeypatch.setattr(managed_node, "_systemd_unit_of", lambda _pid: "blackbox-dkg.service")
    monkeypatch.setattr(managed_node, "_dkg_sync_environment", lambda _cfg: {})
    monkeypatch.setattr(
        managed_node.subprocess,
        "run",
        lambda *_a, **_k: argparse.Namespace(returncode=1, stdout="", stderr="unit masked"),
    )
    cfg = config_mod.BlackboxConfig(dkg_home=str(dkg_home), dkg_bin=str(dkg_home / "dkg"))

    with pytest.raises(RuntimeError, match="unit masked"):
        managed_node._restart_managed_dkg(cfg)


@pytest.mark.parametrize(
    "transient_error",
    [
        'POST /api/shared-memory/catchup -> 502: {"error": "upstream node unreachable"}',
        "POST /api/shared-memory/catchup transport error: <urlopen error [Errno 111] Connection refused>",
    ],
)
def test_authoritative_recovery_rides_out_node_restart_window(
    monkeypatch, tmp_path, transient_error
):
    attempts = []
    states = []

    class FakeClient:
        dkg_home = str(tmp_path)

        def catchup_from_peer(self, cg_id, peer_id, *, budget_ms):
            attempts.append(budget_ms)
            if len(attempts) == 1:
                raise sync_command.DkgError(transient_error)
            (tmp_path / "daemon.log").write_text(
                f'Rootless durable progress for "{cg_id}": '
                "1 complete graph(s), safe offset 0->1 of 1 (raw 1)\n",
                encoding="utf-8",
            )
            return {
                "ok": True, "includeDurable": True, "includeSharedMemory": False,
                "peersAttempted": 1, "results": [{"peerId": peer_id}],
            }

        def threat_count(self, cg_id, *, peer_id=None):
            return 4

    monkeypatch.setattr(sync_command.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        sync_command.sync_state,
        "write",
        lambda status, **details: states.append((status, details)) or details,
    )

    assert sync_command._catchup_authoritative_vm(
        FakeClient(), "owner/graph", "curator", sync_command.time.monotonic() + 60
    )
    assert len(attempts) == 2
    assert not any(status == "failed" for status, _details in states)
