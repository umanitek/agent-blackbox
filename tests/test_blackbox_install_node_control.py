"""The installer starts, stops and restarts the DKG node THROUGH the service that supervises it.

KI-414 (bb-trader-1, 2026-10-15): re-running the one-liner over an install whose node runs under
the `blackbox-dkg` systemd unit restarted it with `dkg stop`/`dkg start` behind the unit's back.
The unit's node exited "failed", systemd restarted it (Restart=on-failure), its ExecStartPre
`dkg stop` killed the installer's own copy, the unit flapped (NRestarts 0 → 3), and the catch-up
that followed failed "Daemon already running" — the run ended "setup is incomplete" on a fully
protected node. launchd (KeepAlive on an unsuccessful exit) and the Windows logon task (retries a
failed run) supervise the node the same way. These tests run the real functions out of the
script with fake `systemctl`, `launchctl` and `uname` that record what they are asked.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO / "scripts" / "blackbox-install.ps1"
LABEL = "ai.umanitek.blackbox-dkg"


def _body(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _fake(bin_dir: Path, name: str, script: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    path.chmod(0o755)


def _control(tmp_path: Path, action: str, *, system_unit: bool = False, user_unit: bool = False,
             enabled: bool = True, darwin: bool = False, plist: bool = False, loaded: bool = False) -> list[str]:
    """Run blackbox_dkg_control *action* in a sandbox; return every recorded call, in order."""
    home, bin_dir, unit_dir, calls = tmp_path / "home", tmp_path / "bin", tmp_path / "systemd", tmp_path / "calls"
    for folder in (home, bin_dir, unit_dir):
        folder.mkdir(parents=True, exist_ok=True)
    calls.write_text("", encoding="utf-8")
    if system_unit:
        (unit_dir / "blackbox-dkg.service").write_text("[Service]\n", encoding="utf-8")
    if user_unit:
        (home / ".config" / "systemd" / "user").mkdir(parents=True)
        (home / ".config" / "systemd" / "user" / "blackbox-dkg.service").write_text("[Service]\n", encoding="utf-8")
    if plist:
        (home / "Library" / "LaunchAgents").mkdir(parents=True)
        (home / "Library" / "LaunchAgents" / f"{LABEL}.plist").write_text("<plist/>", encoding="utf-8")
    log = f'echo "$(basename "$0") $*" >> {shlex.quote(str(calls))}\n'
    if system_unit or user_unit:
        enabled_rc = 0 if enabled else 1
        _fake(bin_dir, "systemctl", log + f'case "$*" in *is-enabled*) exit {enabled_rc};; esac\nexit 0\n')
    _fake(bin_dir, "uname", f'echo {"Darwin" if darwin else "Linux"}\n')
    _fake(bin_dir, "launchctl", log + f'case "$1" in print) exit {0 if loaded else 1};; esac\nexit 0\n')
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = f"""
BLACKBOX_SYSTEMD_DIR={shlex.quote(str(unit_dir))}
BLACKBOX_DKG_LAUNCHD_LABEL={LABEL}
HOME={shlex.quote(str(home))}
PATH={shlex.quote(str(bin_dir))}:/usr/bin:/bin
blackbox_dkg() {{ echo "dkg $*" >> {shlex.quote(str(calls))}; }}
sleep() {{ :; }}
id() {{ if [ "${{1:-}}" = -u ]; then echo {os.getuid()}; else command id "$@"; fi; }}
BLACKBOX_LAUNCHD_GONE_TRIES=3
blackbox_launchd_wait_gone() {{
{_body(text, "blackbox_launchd_wait_gone")}
}}
blackbox_launchd_reload() {{
{_body(text, "blackbox_launchd_reload")}
}}
blackbox_dkg_supervisor() {{
{_body(text, "blackbox_dkg_supervisor")}
}}
blackbox_dkg_control() {{
{_body(text, "blackbox_dkg_control")}
}}
blackbox_dkg_control {action}
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False,
                            env={k: v for k, v in os.environ.items() if k not in ("HOME", "PATH")})
    assert result.returncode == 0, result.stderr
    return [line for line in calls.read_text(encoding="utf-8").splitlines() if not line.startswith("systemctl is-enabled")
            and "is-enabled" not in line and not line.startswith("launchctl print")]


def test_a_node_under_the_systemd_unit_is_restarted_through_systemd(tmp_path):
    assert _control(tmp_path, "restart", system_unit=True) == ["systemctl restart blackbox-dkg"]


def test_a_node_under_the_systemd_unit_is_stopped_and_started_through_systemd(tmp_path):
    assert _control(tmp_path / "a", "stop", system_unit=True) == ["systemctl stop blackbox-dkg"]
    assert _control(tmp_path / "b", "start", system_unit=True) == ["systemctl start blackbox-dkg"]


def test_a_node_under_a_user_unit_is_restarted_through_systemctl_user(tmp_path):
    assert _control(tmp_path, "restart", user_unit=True) == ["systemctl --user restart blackbox-dkg"]


def test_without_a_service_the_installer_runs_the_node_itself(tmp_path):
    """A first install: no service is registered yet, so the DKG CLI starts and stops it."""
    assert _control(tmp_path / "a", "restart") == ["dkg stop", "dkg start"]
    assert _control(tmp_path / "b", "start") == ["dkg start"]


def test_a_unit_that_is_present_but_not_enabled_does_not_own_the_node(tmp_path):
    assert _control(tmp_path, "restart", system_unit=True, enabled=False) == ["dkg stop", "dkg start"]


def test_a_node_under_launchd_is_restarted_through_launchd(tmp_path):
    uid = os.getuid()
    assert _control(tmp_path / "a", "restart", darwin=True, plist=True, loaded=True) == [f"launchctl kickstart -k gui/{uid}/{LABEL}"]
    assert _control(tmp_path / "b", "stop", darwin=True, plist=True, loaded=True) == [f"launchctl bootout gui/{uid}/{LABEL}"]
    started = _control(tmp_path / "c", "start", darwin=True, plist=True, loaded=False)
    assert started == [f"launchctl bootstrap gui/{uid} {tmp_path / 'c' / 'home' / 'Library' / 'LaunchAgents' / f'{LABEL}.plist'}"]


@pytest.mark.parametrize("function", ["install_dkg", "provision_blackbox_store"])
def test_the_installer_never_starts_or_stops_the_node_behind_its_service(function):
    """Every start/stop/restart of the node in these steps goes through blackbox_dkg_control."""
    body = _body(INSTALL_SH.read_text(encoding="utf-8"), function)
    assert not re.search(r"\bblackbox_dkg (start|stop)\b", body), function
    assert "blackbox_dkg_control" in body


def test_the_launchd_label_is_one_constant():
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert f"BLACKBOX_DKG_LAUNCHD_LABEL={LABEL}" in text
    assert "<key>Label</key><string>$BLACKBOX_DKG_LAUNCHD_LABEL</string>" in text


def _ps1_function(name: str) -> str:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    match = re.search(rf"^function {re.escape(name)} \{{\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name} not found"
    return match["body"]


def test_windows_routes_the_node_through_its_logon_task():
    control = _ps1_function("Invoke-BlackboxDkgControl")
    assert "Stop-ScheduledTask -TaskName $DkgTaskName" in control and "Start-ScheduledTask -TaskName $DkgTaskName" in control
    assert "Get-ScheduledTask -TaskName $DkgTaskName" in _ps1_function("Get-BlackboxDkgTask")
    text = INSTALL_PS1.read_text(encoding="utf-8")
    assert 'Register-ScheduledTask -TaskName $DkgTaskName' in text and text.count('"Agent Blackbox DKG node"') == 1
    # outside the control function itself, nothing starts or stops the node directly
    outside = text.replace(control, "")
    assert not re.search(r"Invoke-BlackboxDkg (start|stop)\b", outside)


def test_a_reload_makes_launchd_read_the_restored_definition(tmp_path):
    """E2E recheck 2026-11-21: after a failed update the rollback put the previous plist back and
    then `restart`ed — kickstart runs the definition launchd already holds, the failed attempt's
    (exit 127, node down). `reload` boots it out, waits, and bootstraps the file on disk."""
    uid = os.getuid()
    plist = tmp_path / "home" / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    assert _control(tmp_path, "reload", darwin=True, plist=True, loaded=True) == [
        f"launchctl bootout gui/{uid}/{LABEL}", f"launchctl bootstrap gui/{uid} {plist}"]


def test_a_reload_under_systemd_rereads_the_unit_first(tmp_path):
    assert _control(tmp_path, "reload", system_unit=True) == ["systemctl daemon-reload", "systemctl restart blackbox-dkg"]


def test_a_node_that_does_not_come_up_says_why(tmp_path):
    """The timeout alone hid the cause ("env: node: No such file or directory")."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    dkg_home, bin_dir = tmp_path / "dkg", tmp_path / "bin"
    dkg_home.mkdir(); bin_dir.mkdir()
    (dkg_home / "launchd-errors.log").write_text("".join(f"line {n}\n" for n in range(20)) + "env: node: No such file or directory\n",
                                                encoding="utf-8")
    _fake(bin_dir, "launchctl", 'echo "\tlast exit code = 127: Command not found"\n')
    script = f"""
BLACKBOX_DKG_HOME={shlex.quote(str(dkg_home))}
BLACKBOX_DKG_LAUNCHD_LABEL={LABEL}
PATH={shlex.quote(str(bin_dir))}:/usr/bin:/bin
step() {{ echo "step: $*"; }}
blackbox_dkg_supervisor() {{ echo launchd; }}
{_assignment(text, "BLACKBOX_DKG_ERROR_LINES")}
blackbox_dkg_launchd_error_log() {{
{_body(text, "blackbox_dkg_launchd_error_log")}
}}
explain_dkg_not_ready() {{
{_body(text, "explain_dkg_not_ready")}
}}
explain_dkg_not_ready
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "last exited with: 127: Command not found" in result.stdout
    assert "env: node: No such file or directory" in result.stdout and "line 0" not in result.stdout


def _assignment(text: str, name: str) -> str:
    return next(line for line in text.splitlines() if line.startswith(f"{name}="))
