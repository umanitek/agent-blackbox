"""KI-312: which process is the managed DKG node — never a stale daemon.pid.

On a stock install (bb-main-a, 2026-10-09) daemon.pid named a dead,
auto-spawned daemon (6436) while systemd ran the real node (foreground worker
6046). Everything keyed on the file then misread the node: the settings check
failed, the systemd check found no unit, and every background sync tried a
`dkg stop` behind systemd's back, waited 45 s, failed, and kept the rules
frozen at the first asset. These tests drive that exact shape.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

import pytest

from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.sync import managed_node, node_process

STALE, WORKER, SUPERVISOR, FOREIGN = 6436, 6046, 6045, 7777


@pytest.fixture
def cfg(tmp_path):
    cli = tmp_path / "dkg" / "cli.js"
    cli.parent.mkdir()
    cli.write_text("", encoding="utf-8")
    return BlackboxConfig(dkg_home=str(tmp_path), dkg_bin=str(cli), dkg_url="http://127.0.0.1:9320")


def _processes(monkeypatch, cfg, table: dict[int, list[str]], env: dict[str, str] | None = None):
    """Fake the process table: pid -> command line. Pids not in it are dead."""
    psutil = node_process.psutil

    class Process:
        def __init__(self, pid):
            if pid not in table:
                raise psutil.NoSuchProcess(pid)
            self.pid = pid
            self.info = {"cmdline": table[pid], "exe": "/usr/bin/node"}

        def is_running(self):
            return True

        def cmdline(self):
            return table[self.pid]

        def environ(self):
            return dict(env or {})

    monkeypatch.setattr(psutil, "Process", Process)
    monkeypatch.setattr(psutil, "process_iter", lambda _attrs=None: [Process(pid) for pid in table])


def _ours(cfg, role):
    return ["node", str(Path(cfg.dkg_bin).resolve()), role]


def _pidfile(cfg, pid):
    (Path(cfg.dkg_home) / "daemon.pid").write_text(str(pid), encoding="utf-8")


def test_a_stale_pidfile_resolves_to_the_live_systemd_worker(cfg, monkeypatch):
    _processes(monkeypatch, cfg, {WORKER: _ours(cfg, "daemon-foreground-worker")})
    _pidfile(cfg, STALE)

    assert node_process.managed_daemon_pid(cfg) == WORKER


def test_a_live_pidfile_daemon_is_used_as_is(cfg, monkeypatch):
    _processes(monkeypatch, cfg, {WORKER: _ours(cfg, "daemon-worker"), SUPERVISOR: _ours(cfg, "daemon-supervisor")})
    _pidfile(cfg, SUPERVISOR)

    assert node_process.managed_daemon_pid(cfg) == SUPERVISOR


def test_a_pidfile_naming_some_other_process_is_ignored(cfg, monkeypatch):
    _processes(monkeypatch, cfg, {FOREIGN: ["python", "server.py"], WORKER: _ours(cfg, "daemon-worker")})
    _pidfile(cfg, FOREIGN)

    assert node_process.managed_daemon_pid(cfg) == WORKER


def test_the_worker_is_preferred_over_the_supervisor(cfg, monkeypatch):
    _processes(monkeypatch, cfg, {SUPERVISOR: _ours(cfg, "daemon-supervisor"), WORKER: _ours(cfg, "daemon-worker")})

    assert node_process.managed_daemon_pid(cfg) == WORKER


def test_another_installations_node_is_never_ours(cfg, monkeypatch):
    _processes(monkeypatch, cfg, {FOREIGN: ["node", "/opt/other/dkg/cli.js", "daemon-worker"]})

    assert node_process.managed_daemon_pid(cfg) is None


def test_the_settings_check_reads_the_live_worker_not_the_stale_pidfile(cfg, monkeypatch):
    settings = {"DKG_SYNC_ON_CONNECT_ENABLED": "1"}
    _processes(monkeypatch, cfg, {WORKER: _ours(cfg, "daemon-foreground-worker")}, env=settings)
    _pidfile(cfg, STALE)

    assert managed_node._managed_dkg_sync_mode_matches(cfg, settings) is True


def test_a_restart_with_a_stale_pidfile_goes_through_systemd(cfg, monkeypatch):
    """The bb-main-a loop: before the fix this ran `dkg stop` behind systemd's back."""
    _processes(monkeypatch, cfg, {WORKER: _ours(cfg, "daemon-foreground-worker")})
    _pidfile(cfg, STALE)
    commands = []

    def run(command, **_kwargs):
        commands.append(list(command))
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(managed_node, "_systemd_unit_of", lambda pid: "blackbox-dkg.service" if pid == WORKER else None)
    monkeypatch.setattr(managed_node, "_dkg_sync_environment", lambda _cfg: {})
    monkeypatch.setattr(managed_node.subprocess, "run", run)
    monkeypatch.setattr(managed_node, "_wait_for_managed_dkg_ready", lambda _cfg, _detail: None)

    managed_node._restart_managed_dkg(cfg)

    assert commands == [["systemctl", "restart", "blackbox-dkg.service"]]


def test_a_node_started_inside_the_restart_wait_is_starting(monkeypatch, cfg):
    """2026-11-08: after a reboot the node answers only once its store has reopened; until then
    health says it is starting. A node older than the wait, or none at all, is not."""
    import time as clock

    started = {"at": clock.time() - 30}

    class Process:
        def __init__(self, pid):
            if pid != 4242:
                raise node_process.psutil.NoSuchProcess(pid)

        def create_time(self):
            return started["at"]

    monkeypatch.setattr(node_process.psutil, "Process", Process)
    monkeypatch.setattr(node_process, "managed_daemon_pid", lambda c: 4242)
    assert node_process.node_starting(cfg, 300) is True
    started["at"] = clock.time() - 600
    assert node_process.node_starting(cfg, 300) is False
    monkeypatch.setattr(node_process, "managed_daemon_pid", lambda c: None)
    assert node_process.node_starting(cfg, 300) is False

