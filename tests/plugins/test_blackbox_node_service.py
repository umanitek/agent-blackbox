"""The DKG node is restarted through the boot service registered to run it (KI-426).

On the GitHub macOS runner (2026-10-15) the installer stopped its own node to hand it to the
LaunchAgent; 15 s later the dashboard's scheduled `blackbox sync` found the node down, saw no
systemd unit (the only service it knew) and started a detached node itself — launchd's copy then
failed "Daemon already running" on every relaunch. The service is now found by registration
(the LaunchAgent / unit that runs THIS install's dkg_bin), so a down node is restarted through it,
and a node running outside it is stopped first.
"""

from __future__ import annotations

import argparse
import plistlib
import re
import shlex
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.sync import managed_node, node_service

REPO = Path(__file__).resolve().parents[2]
LABEL = "ai.umanitek.blackbox-dkg"
SERVICE_PID, NODE_PID, STRAY_PID = 7000, 7001, 4527


@pytest.fixture
def cfg(tmp_path) -> config_mod.BlackboxConfig:
    dkg_home = tmp_path / "dkg-home"
    dkg_home.mkdir()
    dkg_bin = tmp_path / "node_modules" / ".bin" / "dkg"
    dkg_bin.parent.mkdir(parents=True)
    dkg_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    return config_mod.BlackboxConfig(dkg_home=str(dkg_home), dkg_bin=str(dkg_bin))


class FakeManager:
    """Records commands; answers `launchctl print` / `systemctl show|is-enabled` like a real manager."""

    def __init__(self, *, loaded: bool = True, enabled: bool = True, service_pid: int | None = SERVICE_PID) -> None:
        self.loaded, self.enabled, self.service_pid = loaded, enabled, service_pid
        self.commands: list[list[str]] = []

    def run(self, command, **_kwargs):
        command = [str(part) for part in command]
        self.commands.append(command)
        pid = self.service_pid or 0
        if command[:2] == ["launchctl", "print"]:
            return argparse.Namespace(returncode=0 if self.loaded else 113, stdout=f"{LABEL} = {{\n\tstate = running\n\tpid = {pid}\n}}\n", stderr="")
        if "is-enabled" in command:
            return argparse.Namespace(returncode=0 if self.enabled else 1, stdout="", stderr="")
        if "show" in command:
            return argparse.Namespace(returncode=0, stdout=f"{pid}\n", stderr="")
        return argparse.Namespace(returncode=0, stdout="", stderr="")


@pytest.fixture
def manager(monkeypatch) -> FakeManager:
    fake = FakeManager()
    monkeypatch.setattr(node_service.subprocess, "run", fake.run)
    return fake


def _launch_agent(home: Path, program: str) -> None:
    folder = home / "Library" / "LaunchAgents"
    folder.mkdir(parents=True)
    (folder / f"{LABEL}.plist").write_bytes(plistlib.dumps({"Label": LABEL, "ProgramArguments": [program, "start", "--foreground"]}))


def _unit(folder: Path, program: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "blackbox-dkg.service").write_text(f"[Service]\nExecStart={program} start --foreground\n", encoding="utf-8")


# ── finding the service by registration ──────────────────────────────────────

def test_a_loaded_launch_agent_for_this_install_is_the_node_s_service(cfg, tmp_path, manager, monkeypatch):
    monkeypatch.setattr(node_service.sys, "platform", "darwin")   # os-marker: ok — only picks the launchd strategy; launchctl is stubbed and the plist is in tmp_path
    _launch_agent(tmp_path, cfg.dkg_bin)
    service = node_service.registered(cfg, home=tmp_path)
    assert service is not None and service.name == LABEL
    assert service.restart_argv[:3] == ("launchctl", "kickstart", "-k")
    assert service.restart_argv[3].endswith(f"/{LABEL}")


def _installer_launcher(home: Path, name: str, *programs: str) -> str:
    """The launcher exactly as the installer writes it (its real write_service_launcher)."""
    text = (REPO / "scripts" / "blackbox-install.sh").read_text(encoding="utf-8")
    function = re.search(r"^write_service_launcher\(\) \{.*?\n\}", text, re.MULTILINE | re.DOTALL).group(0)
    script = f"{function}\nBLACKBOX_HOME={shlex.quote(str(home))}\nwrite_service_launcher " + " ".join(
        shlex.quote(part) for part in (name, *programs))
    # Popen, not run: the `manager` fixture stubs subprocess.run for launchctl.
    with subprocess.Popen(["bash", "-c", script], stdout=subprocess.PIPE, text=True) as process:
        out, _ = process.communicate()
    assert process.returncode == 0
    return out.strip()


def test_the_launch_agent_the_installer_writes_through_its_launcher_is_this_install_s_service(cfg, tmp_path, manager, monkeypatch):
    """KI-529: the plist runs <BLACKBOX_HOME>/bin/"Blackbox Node" (FIX-0255), not dkg itself. Reading
    only the first argument found no service, so the dashboard's sync started the node behind launchd
    and launchd's copy failed "Daemon already running" — a fresh install then rolled back."""
    monkeypatch.setattr(node_service.sys, "platform", "darwin")   # os-marker: ok — only picks the launchd strategy; launchctl is stubbed and the plist is in tmp_path
    launcher = _installer_launcher(tmp_path / "blackbox-home", "Blackbox Node", cfg.dkg_bin)
    _launch_agent(tmp_path, launcher)
    service = node_service.registered(cfg, home=tmp_path)
    assert service is not None and service.name == LABEL


def test_a_launcher_for_another_install_s_node_is_not_ours(cfg, tmp_path, manager, monkeypatch):
    monkeypatch.setattr(node_service.sys, "platform", "darwin")   # os-marker: ok — only picks the launchd strategy; launchctl is stubbed and the plist is in tmp_path
    launcher = _installer_launcher(tmp_path / "blackbox-home", "Blackbox Node", "/opt/other install/.bin/dkg")
    _launch_agent(tmp_path, launcher)
    assert node_service.registered(cfg, home=tmp_path) is None


def test_a_launch_agent_for_another_install_is_not_ours(cfg, tmp_path, manager, monkeypatch):
    monkeypatch.setattr(node_service.sys, "platform", "darwin")   # os-marker: ok — only picks the launchd strategy; launchctl is stubbed and the plist is in tmp_path
    _launch_agent(tmp_path, "/opt/other-install/node_modules/.bin/dkg")
    assert node_service.registered(cfg, home=tmp_path) is None


def test_a_launch_agent_that_is_not_loaded_is_started_by_loading_it_never_directly(cfg, tmp_path, monkeypatch):
    """KI-529: after Stop (bootout) or the handover's fallback the agent is registered but not
    loaded. Treating that as "no service" let a sync start an unsupervised node, which launchd's
    own copy then fought ("Daemon already running") the moment the agent loaded."""
    monkeypatch.setattr(node_service.sys, "platform", "darwin")   # os-marker: ok — only picks the launchd strategy; launchctl is stubbed and the plist is in tmp_path
    monkeypatch.setattr(node_service.subprocess, "run", FakeManager(loaded=False).run)
    _launch_agent(tmp_path, cfg.dkg_bin)
    service = node_service.registered(cfg, home=tmp_path)
    assert service is not None and service.name == LABEL
    assert service.restart_argv[:2] == ("launchctl", "bootstrap")
    assert service.restart_argv[-1] == str(tmp_path / "Library" / "LaunchAgents" / f"{LABEL}.plist")


def test_an_enabled_system_unit_for_this_install_is_the_node_s_service(cfg, tmp_path, manager, monkeypatch):
    monkeypatch.setattr(node_service.sys, "platform", "linux")
    monkeypatch.setattr(node_service, "SYSTEM_UNIT_DIR", tmp_path / "etc-systemd")
    _unit(tmp_path / "etc-systemd", cfg.dkg_bin)
    service = node_service.registered(cfg, home=tmp_path)
    assert service is not None and service.restart_argv == ("systemctl", "restart", "blackbox-dkg")


def test_a_user_unit_is_restarted_with_systemctl_user(cfg, tmp_path, manager, monkeypatch):
    monkeypatch.setattr(node_service.sys, "platform", "linux")
    monkeypatch.setattr(node_service, "SYSTEM_UNIT_DIR", tmp_path / "absent")
    _unit(tmp_path / ".config" / "systemd" / "user", cfg.dkg_bin)
    service = node_service.registered(cfg, home=tmp_path)
    assert service is not None and service.restart_argv == ("systemctl", "--user", "restart", "blackbox-dkg")


@pytest.mark.parametrize("program, enabled", [("/opt/other/dkg", True), (None, False)])
def test_a_unit_for_another_install_or_not_enabled_is_not_ours(cfg, tmp_path, monkeypatch, program, enabled):
    monkeypatch.setattr(node_service.sys, "platform", "linux")
    monkeypatch.setattr(node_service, "SYSTEM_UNIT_DIR", tmp_path / "etc-systemd")
    monkeypatch.setattr(node_service.subprocess, "run", FakeManager(enabled=enabled).run)
    _unit(tmp_path / "etc-systemd", program or cfg.dkg_bin)
    assert node_service.registered(cfg, home=tmp_path) is None


# ── which process the service runs ───────────────────────────────────────────

GRANDCHILD_PID, MIDDLE_PID = 7003, 7002
#: Each simulated process's parent: the service runs a launcher whose CLI runs the daemon.
PARENTS = {NODE_PID: SERVICE_PID, MIDDLE_PID: SERVICE_PID, GRANDCHILD_PID: MIDDLE_PID, STRAY_PID: 4500, 4500: 1}
#: The environment the service started its node with (a LaunchAgent's EnvironmentVariables).
SERVICE_ENVIRONMENT = {"DKG_SYNC_ON_CONNECT_ENABLED": "1"}


class _Process:
    def __init__(self, pid: int) -> None:
        if pid not in PARENTS and pid != SERVICE_PID:
            raise node_service.psutil.NoSuchProcess(pid)
        self.pid = pid

    def ppid(self) -> int:
        return PARENTS.get(self.pid, 1)

    def environ(self) -> dict[str, str]:
        return dict(SERVICE_ENVIRONMENT) if self.pid in (NODE_PID, GRANDCHILD_PID) else {}


@pytest.mark.parametrize("pid, owned", [(SERVICE_PID, True), (NODE_PID, True), (GRANDCHILD_PID, True), (STRAY_PID, False),
                                        (None, False)])
def test_the_service_owns_its_process_and_that_process_s_child(manager, monkeypatch, pid, owned):
    """KI-541 (E2E full5 2026-11-22): under launchd the daemon is the service's GRANDCHILD
    (launcher -> `dkg start --foreground` -> daemon); a parent-only check missed it."""
    monkeypatch.setattr(node_service.psutil, "Process", _Process)
    assert node_service.systemd_unit("blackbox-dkg.service").owns(pid) is owned


def test_a_service_that_runs_nothing_owns_nothing(monkeypatch):
    monkeypatch.setattr(node_service.subprocess, "run", FakeManager(service_pid=None).run)
    assert node_service.systemd_unit("blackbox-dkg.service").owns(NODE_PID) is False


# ── restarting through it ────────────────────────────────────────────────────

LAUNCHD = node_service.NodeService(LABEL, ("launchctl", "print", f"gui/501/{LABEL}"), ("launchctl", "kickstart", "-k", f"gui/501/{LABEL}"))


@pytest.fixture
def restart_world(cfg, manager, monkeypatch):
    """_restart_managed_dkg with the LaunchAgent registered; returns the list of stops it made."""
    stops: list[int | None] = []
    monkeypatch.setattr(managed_node, "_systemd_unit_of", lambda _pid: None)
    monkeypatch.setattr(managed_node, "_dkg_sync_environment", lambda _cfg: {})
    monkeypatch.setattr(managed_node, "_wait_for_managed_dkg_ready", lambda _cfg, _detail: None)
    monkeypatch.setattr(managed_node, "_stop_managed_dkg", lambda _cfg, pid, _env, _command: stops.append(pid))
    monkeypatch.setattr(managed_node.node_service, "registered", lambda _cfg: LAUNCHD)
    monkeypatch.setattr(node_service.psutil, "Process", _Process)
    return stops


def test_a_node_started_outside_the_launch_agent_is_stopped_then_restarted_through_it(cfg, manager, restart_world, monkeypatch):
    """The CI race: a stray detached node is running; launchd must get the node, not a second stray."""
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: STRAY_PID)
    managed_node._restart_managed_dkg(cfg)
    assert restart_world == [STRAY_PID]
    assert manager.commands[-1] == list(LAUNCHD.restart_argv)
    assert [str(cfg.dkg_bin), "start"] not in manager.commands


def test_a_down_node_is_started_through_the_launch_agent_not_directly(cfg, manager, restart_world, monkeypatch):
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: None)
    managed_node._restart_managed_dkg(cfg)
    assert restart_world == []
    assert manager.commands[-1] == list(LAUNCHD.restart_argv)


def test_a_node_the_launch_agent_runs_is_just_kickstarted(cfg, manager, restart_world, monkeypatch):
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: NODE_PID)
    managed_node._restart_managed_dkg(cfg)
    assert restart_world == []
    assert manager.commands[-1] == list(LAUNCHD.restart_argv)


def test_a_failed_kickstart_raises_with_its_detail(cfg, restart_world, monkeypatch):
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: None)
    monkeypatch.setattr(node_service.subprocess, "run", lambda *_a, **_k: argparse.Namespace(returncode=5, stdout="", stderr="Could not find service"))
    with pytest.raises(RuntimeError, match=f"could not restart {LABEL}: Could not find service"):
        managed_node._restart_managed_dkg(cfg)


def test_a_node_under_the_launch_agent_is_not_restarted_for_settings_only_its_plist_can_set(cfg, manager, restart_world, monkeypatch):
    """Otherwise every hourly sync would kickstart it (the KI-059/065 loop, now on macOS)."""
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: NODE_PID)
    expected = managed_node.expected_node_settings(cfg)
    assert not set(expected) & set(managed_node._DKG_ENV_ONLY_SETTINGS)


def test_a_setting_the_service_pins_is_not_a_reason_to_restart_through_it(cfg, manager, restart_world, monkeypatch, caplog):
    """KI-541 (E2E full5 2026-11-22): the LaunchAgent pins sync-on-connect ON (KI-044) while the
    snapshot profile asks for it off. A restart through the service starts the node with the same
    environment, so the sync kickstarted the node again and again for a value it can never change."""
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: GRANDCHILD_PID)
    monkeypatch.setattr(managed_node, "node_sync_settings",
                        lambda _cfg: {"DKG_SYNC_ON_CONNECT_ENABLED": "0", "DKG_VM_RECOVERY_PREFETCH_ENABLED": "0"})
    with caplog.at_level("WARNING"):
        expected = managed_node.expected_node_settings(cfg)
    assert expected == {"DKG_VM_RECOVERY_PREFETCH_ENABLED": "0"}   # not pinned: still held to the profile
    assert "DKG_SYNC_ON_CONNECT_ENABLED" in caplog.text


def test_a_stray_node_is_held_to_every_setting(cfg, manager, restart_world, monkeypatch):
    """A node started outside the service has the installer's settings: the sync must restart it."""
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: STRAY_PID)
    assert managed_node.expected_node_settings(cfg) == managed_node.node_sync_settings(cfg)


def test_the_launchd_label_matches_the_installer():
    installer = (REPO / "scripts" / "blackbox-install.sh").read_text(encoding="utf-8")
    match = re.search(r"^BLACKBOX_DKG_LAUNCHD_LABEL=(\S+)", installer, re.MULTILINE)
    assert match is not None and match.group(1) == node_service.LAUNCHD_LABEL == LABEL


# ── the LaunchAgent error log stays bounded ──────────────────────────────────

def test_a_large_error_log_is_trimmed_in_place_to_its_newest_whole_lines(tmp_path):
    """launchd keeps the file open for appending: the trim must keep the same file, not replace it."""
    log = tmp_path / node_service.LAUNCHD_ERROR_LOG
    log.write_bytes(b"".join(f"warning {number:06d}\n".encode() for number in range(20_000)))
    inode = log.stat().st_ino
    with log.open("ab") as launchd_handle:   # what launchd holds
        assert node_service.trim_error_log(tmp_path, max_bytes=100_000, keep_bytes=10_000) is True
        launchd_handle.write(b"written after the trim\n")
    text = log.read_bytes()
    assert log.stat().st_ino == inode
    assert len(text) < 10_100
    assert text.startswith(b"warning ") and text.endswith(b"warning 019999\nwritten after the trim\n")


def test_a_small_or_missing_error_log_is_left_alone(tmp_path):
    log = tmp_path / node_service.LAUNCHD_ERROR_LOG
    assert node_service.trim_error_log(tmp_path) is False   # missing
    log.write_bytes(b"Daemon already running (PID 1).\n")
    assert node_service.trim_error_log(tmp_path) is False
    assert log.read_bytes() == b"Daemon already running (PID 1).\n"


def test_every_blackbox_sync_trims_the_error_log(cfg, monkeypatch):
    from plugins.blackbox import sync

    trimmed: list[Path] = []
    monkeypatch.setattr(sync, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(sync.health, "node_installed", lambda _cfg, _reachable: True)
    monkeypatch.setattr(sync.DkgClient, "reachable", lambda self, **_kwargs: True)
    monkeypatch.setattr(sync.node_service, "trim_error_log", lambda home: trimmed.append(home))
    monkeypatch.setattr(sync, "_sync_with_node", lambda _args: 0)
    assert sync.cmd_sync(argparse.Namespace(wait=False)) == 0
    assert trimmed == [Path(cfg.dkg_home)]


def test_the_error_log_name_matches_the_installer():
    installer = (REPO / "scripts" / "blackbox-install.sh").read_text(encoding="utf-8")
    assert f"printf '%s/{node_service.LAUNCHD_ERROR_LOG}' \"$BLACKBOX_DKG_HOME\"" in installer
