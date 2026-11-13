"""`blackbox uninstall` removes Blackbox from a machine and nothing else (2026-11-03).

Until now there was no way out but `detach`. The machine below is the Hermes Desktop install
proven live that day: Desktop's Hermes home with a commented config and Hermes's own record of
the plugin, Blackbox's node (marker, wallet and identity files, pid file) and reporter key, our
`blackbox` launcher beside Desktop's `hermes`, a Foreman-style node in ~/.dkg that must survive,
and the two login services. Service commands are recorded, never run.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from plugins.blackbox.setup import uninstall

CONFIG = """\
# Hermes Agent CLI Configuration
model:
  default: nous/hermes-4   # the model
plugins:
  enabled:
    - blackbox
    - browser
  entries:
    blackbox:
      mode: audit
      dkg_home: {dkg_home}
"""


@pytest.fixture()
def machine(tmp_path, monkeypatch):
    home = tmp_path / "user"
    hermes = home / ".hermes"
    bb = hermes / "blackbox"
    dkg = bb / "node" / ".dkg"
    for d in (hermes / "plugins" / "blackbox", dkg, home / ".local" / "bin", home / ".dkg",
              home / "Library" / "LaunchAgents"):
        d.mkdir(parents=True, exist_ok=True)
    (hermes / "config.yaml").write_text(CONFIG.format(dkg_home=dkg), encoding="utf-8")
    (hermes / "plugins" / ".install-metadata.json").write_text(json.dumps({"blackbox": {"pinned": True}}), encoding="utf-8")
    (dkg / uninstall.DKG_HOME_MARKER).write_text("{}", encoding="utf-8")
    for name in uninstall.NODE_KEY_FILES:
        (dkg / name).write_text(f"secret {name}", encoding="utf-8")
    (dkg / "daemon.pid").write_text("2147483646", encoding="utf-8")       # no such process
    (bb / "reporter_key.pem").write_text("reporter", encoding="utf-8")
    (bb / "sharing_consent.json").write_text("{}", encoding="utf-8")
    (bb / "audit.jsonl").write_text('{"event": 1}\n', encoding="utf-8")
    (home / ".local" / "bin" / "blackbox").write_text(f"#!/bin/sh\n# {uninstall.SHIM_MARKER}\n", encoding="utf-8")
    (home / ".local" / "bin" / "hermes").write_text("#!/bin/sh\nexec desktop-hermes\n", encoding="utf-8")
    (home / ".dkg" / "config.json").write_text("foreman", encoding="utf-8")
    for label in uninstall.LAUNCHD_LABELS:
        (home / "Library" / "LaunchAgents" / f"{label}.plist").write_text("<plist/>", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    return home


def _plan(machine: Path, *, system: str = "Darwin", **kw) -> uninstall.UninstallPlan:
    plan = uninstall.build_plan(homes=[machine / ".hermes"], purge=kw.pop("purge", False),
                                keep_logs=kw.pop("keep_logs", False))
    return dataclasses.replace(plan, system=system)


def _execute(plan: uninstall.UninstallPlan, *, dashboard_pids: tuple[int, ...] = ()):
    calls: list[list[str]] = []

    def stop_dashboard(port: int) -> list[int]:
        calls.append(["stop-dashboard", str(port), str(plan.blackbox_home.exists())])
        return list(dashboard_pids)

    report = uninstall.execute(plan, run=lambda cmd: calls.append(list(cmd)) or 0, stop_dashboard=stop_dashboard)
    return calls, report


def test_the_plan_says_what_goes_and_what_stays(machine):
    lines = "\n".join(uninstall.describe(_plan(machine)))
    assert "remove Blackbox from the Hermes in" in lines and "blackbox-backup-" in lines
    assert str(machine / ".dkg") not in lines
    assert "Your Hermes itself, other DKG nodes and Docker are not touched." in lines


def test_uninstall_removes_blackbox_and_keeps_the_keys(machine):
    plan = _plan(machine)
    calls, _ = _execute(plan)

    hermes = machine / ".hermes"
    assert not (hermes / "blackbox").exists()                                  # data + node + graph
    assert not (machine / ".local" / "bin" / "blackbox").exists()
    assert not list((machine / "Library" / "LaunchAgents").glob("ai.umanitek.*"))
    assert [c[:2] for c in calls[:2]] == [["launchctl", "bootout"]] * 2
    # the running code goes last, removed by the Hermes that is running (never another one on PATH)
    assert calls[-1][-6:] == [sys.executable, "-m", "hermes_cli.main", "plugins", "remove", "blackbox"]
    config = (hermes / "config.yaml").read_text(encoding="utf-8")
    assert "blackbox" not in config and "# the model" in config and "browser" in config
    # kept, private, and explained
    keys = plan.backup_dir / "keys"
    assert {p.name for p in keys.iterdir()} == {f"node-{n}" for n in uninstall.NODE_KEY_FILES} | {
        "reporter_key.pem", "sharing_consent.json"}
    assert stat.S_IMODE(os.stat(keys / "node-wallets.key").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(plan.backup_dir).st_mode) == 0o700
    assert "To use the same node identity again" in (plan.backup_dir / "README.txt").read_text(encoding="utf-8")
    # not ours, not touched
    assert (machine / ".local" / "bin" / "hermes").exists()
    assert (machine / ".dkg" / "config.json").read_text(encoding="utf-8") == "foreman"


def test_purge_leaves_no_keys_anywhere(machine):
    plan = _plan(machine, purge=True)
    _execute(plan)
    assert plan.backup_dir is None
    assert not list(machine.glob("blackbox-backup-*"))
    assert not (machine / ".hermes" / "blackbox").exists()


def test_keep_logs_puts_the_audit_record_in_the_backup(machine):
    plan = _plan(machine, keep_logs=True)
    _execute(plan)
    assert (plan.backup_dir / "audit-record" / "audit.jsonl").read_text(encoding="utf-8") == '{"event": 1}\n'


def test_a_dkg_home_without_blackboxs_marker_is_never_deleted(machine):
    other = machine / "elsewhere" / ".dkg"
    other.mkdir(parents=True)
    (other / "config.json").write_text("someone else's node", encoding="utf-8")
    config = machine / ".hermes" / "config.yaml"
    config.write_text(CONFIG.format(dkg_home=other), encoding="utf-8")
    plan = _plan(machine)
    assert plan.dkg_home != other and any("no Blackbox marker" in n for n in plan.notes)
    _execute(plan)
    assert (other / "config.json").exists()


def test_a_blackbox_command_we_did_not_write_is_left_alone(machine):
    shim = machine / ".local" / "bin" / "blackbox"
    shim.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    plan = _plan(machine)
    assert plan.shim is None
    _execute(plan)
    assert shim.exists()


def test_linux_user_services_go_and_system_units_are_named_with_their_root_commands(machine, tmp_path):
    user_units = machine / ".config" / "systemd" / "user"
    user_units.mkdir(parents=True)
    for unit in uninstall.SYSTEMD_UNITS:
        (user_units / unit).write_text("[Unit]", encoding="utf-8")
    system_unit = tmp_path / "etc" / "blackbox-dkg.service"
    system_unit.parent.mkdir()
    system_unit.write_text("[Unit]", encoding="utf-8")
    plan = dataclasses.replace(_plan(machine, system="Linux"), system_units=(system_unit,))
    calls, report = _execute(plan)
    assert not list(user_units.iterdir())
    assert ["systemctl", "--user", "disable", "--now", "blackbox-dkg.service"] in calls
    assert any(r.startswith("needs root: sudo systemctl disable --now blackbox-dkg.service") for r in report)
    assert system_unit.exists()


def test_windows_tasks_are_ended_and_deleted(machine):
    calls, _ = _execute(_plan(machine, system="Windows"))
    for task in uninstall.WINDOWS_TASKS:
        assert ["schtasks", "/Delete", "/TN", task, "/F"] in calls


def test_without_a_terminal_nothing_is_removed_without_yes(machine, monkeypatch, capsys):
    monkeypatch.setattr(uninstall.terminal_question, "ask", lambda prompt: None)   # no terminal to ask
    args = argparse.Namespace(purge=False, keep_logs=False, dry_run=False, yes=False)
    assert uninstall.cmd_uninstall(args) == 1
    assert (machine / ".hermes" / "blackbox").exists()
    assert "without a yes" in capsys.readouterr().out


def test_a_dashboard_started_without_its_service_is_stopped_before_the_data_goes(machine):
    """Live 2026-11-03: setup starts the dashboard directly; uninstall removed the service, the
    dashboard kept running and re-created ~/.hermes/blackbox right after it was deleted."""
    config = machine / ".hermes" / "config.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace("      mode: audit", "      mode: audit\n      dashboard_port: 9711"),
                      encoding="utf-8")
    plan = _plan(machine)
    assert plan.dashboard_port == 9711
    calls, report = _execute(plan, dashboard_pids=(4242,))
    assert ["stop-dashboard", "9711", "True"] in calls          # asked while the data still existed
    assert "stopped Blackbox's dashboard (pid 4242)" in report


def test_only_a_blackbox_dashboard_on_the_port_is_stopped(monkeypatch):
    from plugins.blackbox.dashboard import command
    stopped: list[set[int]] = []
    monkeypatch.setattr(command, "_listening_pids", lambda port: {11, 22})
    monkeypatch.setattr(command, "_is_blackbox_dashboard", lambda pid: pid == 11)
    monkeypatch.setattr(command, "_stop", lambda pids: stopped.append(set(pids)))
    assert command.stop_running_dashboard(9700) == [11]
    assert stopped == [{11}]                                       # 22 is someone else's: left alone


# --- KI-496: daemon.pid is a hint; only this installation's node is ever signalled ---

@pytest.fixture()
def node_pid_file(machine, monkeypatch):
    """The machine's plan with daemon.pid = 4242, and os.kill recorded instead of run."""
    plan = _plan(machine)
    (plan.dkg_home / "daemon.pid").write_text("4242\n", encoding="utf-8")
    signalled: list[int] = []
    monkeypatch.setattr(uninstall.os, "kill", lambda pid, sig: signalled.append(pid))
    return plan, signalled


def test_a_pid_that_is_not_our_node_is_never_signalled(node_pid_file, monkeypatch):
    from plugins.blackbox import sync
    plan, signalled = node_pid_file
    monkeypatch.setattr(sync, "is_node_process", lambda cfg, pid: False)
    report: list[str] = []

    uninstall._stop_unsupervised_node(plan, report)

    assert signalled == [] and report == []


def test_our_own_node_is_stopped(node_pid_file, monkeypatch):
    from plugins.blackbox import sync
    plan, signalled = node_pid_file
    monkeypatch.setattr(sync, "is_node_process", lambda cfg, pid: pid == 4242)
    report: list[str] = []

    uninstall._stop_unsupervised_node(plan, report)

    assert signalled == [4242] and report == ["stopped Blackbox's DKG node (pid 4242)"]


def test_the_real_check_refuses_a_live_process_that_is_not_a_dkg_node(node_pid_file):
    plan, signalled = node_pid_file
    (plan.dkg_home / "daemon.pid").write_text(str(os.getpid()), encoding="utf-8")   # this test run itself

    uninstall._stop_unsupervised_node(plan, [])

    assert signalled == []


def test_uninstall_and_the_node_service_name_the_same_services():
    """The names were typed in both modules: renaming one in the installer meant two edits."""
    from plugins.blackbox import sync
    from plugins.blackbox.sync import node_service

    assert uninstall.LAUNCHD_LABELS is sync.LAUNCHD_LABELS and uninstall.SYSTEMD_UNITS is sync.SYSTEMD_UNITS
    assert node_service.LAUNCHD_LABEL in uninstall.LAUNCHD_LABELS
    assert f"{node_service.SYSTEMD_UNIT}.service" in uninstall.SYSTEMD_UNITS
    # The values the installers register (scripts/blackbox-install.sh): changing one here is a change there.
    assert uninstall.LAUNCHD_LABELS == ("ai.umanitek.blackbox-dashboard", "ai.umanitek.blackbox-dkg")
    assert uninstall.SYSTEMD_UNITS == ("blackbox-dashboard.service", "blackbox-dkg.service")
    assert uninstall.WINDOWS_TASKS == ("Agent Blackbox dashboard", "Agent Blackbox DKG node")


@pytest.mark.parametrize("plugins", ["blackbox", ["blackbox"], 7])
def test_a_config_whose_plugins_is_not_a_mapping_does_not_crash_the_plan(tmp_path, plugins):
    """`blackbox uninstall` built its plan by reading `plugins.enabled`; a `plugins` that is a
    string or list (a hand-edited config) raised AttributeError and the command crashed."""
    from plugins.blackbox.kernel import yaml_files

    home = tmp_path / "hermes"
    home.mkdir()
    yaml_files.dump_yaml(home / "config.yaml", {"plugins": plugins})
    assert uninstall._names_blackbox(home) is False


@pytest.mark.parametrize("plugins", ["blackbox", ["blackbox"]])
def test_a_config_whose_plugins_is_not_a_mapping_does_not_crash_the_removal(machine, plugins):
    """The plan survived such a config, but the removal step walked plugins.entries by hand and
    raised AttributeError half-way through — after the services were already stopped."""
    from plugins.blackbox.kernel import yaml_files

    yaml_files.dump_yaml(machine / ".hermes" / "config.yaml", {"plugins": plugins})
    _execute(_plan(machine))   # the plugin folder still names this home as Blackbox's
    assert yaml_files.load_yaml(machine / ".hermes" / "config.yaml") == {"plugins": plugins}   # nothing to remove: untouched


def test_uninstall_also_removes_blackbox_from_its_own_chat_profile(machine):
    """`blackbox chat` attaches Blackbox to its managed profile (~/.hermes/profiles/agent-blackbox).
    Discovery hides that profile from the dashboard, and uninstall found homes only through
    discovery, so the plugin copy and its `plugins.enabled` entry survived an uninstall."""
    from plugins.blackbox.kernel import constants, yaml_files

    chat = machine / ".hermes" / "profiles" / constants.BLACKBOX_CHAT_PROFILE
    (chat / "plugins" / "blackbox").mkdir(parents=True)
    (chat / "config.yaml").write_text("plugins:\n  enabled:\n    - blackbox\n", encoding="utf-8")
    (chat / "SOUL.md").write_text(constants.BLACKBOX_CHAT_SOUL_MARKER + "\n", encoding="utf-8")   # as `blackbox chat` writes it
    plan = dataclasses.replace(uninstall.build_plan(purge=False, keep_logs=False), system="Darwin")
    assert chat in plan.hermes_homes
    _execute(plan)
    assert not (chat / "plugins" / "blackbox").exists()
    assert "blackbox" not in (yaml_files.load_yaml(chat / "config.yaml").get("plugins") or {}).get("enabled", [])


@pytest.mark.parametrize("answer, removed", [("y\n", True), ("n\n", False)])
def test_under_a_pipe_the_question_goes_to_the_terminal(machine, monkeypatch, answer, removed):
    """Under `curl … | bash` stdin is the pipe; uninstall refused outright although a terminal
    was there. It now asks the terminal the way `blackbox attach` does (kernel.terminal_question)."""
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))   # the pipe: never read as the answer

    class Terminal(io.StringIO):   # what the operator types; what is written to it is the prompt
        def write(self, text):
            return len(text)

    monkeypatch.setattr(uninstall.terminal_question, "open", lambda *a, **k: Terminal(answer), raising=False)
    executed = []
    monkeypatch.setattr(uninstall, "execute", lambda plan: executed.append(plan) or [])   # only the decision is tested
    args = argparse.Namespace(purge=False, keep_logs=False, dry_run=False, yes=False)
    assert uninstall.cmd_uninstall(args) == 0
    assert bool(executed) is removed
