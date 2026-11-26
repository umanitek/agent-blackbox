"""`blackbox uninstall` removes Blackbox from a machine and nothing else (2026-11-03).

Until now there was no way out but `detach`. The machine below is the Hermes Desktop install
proven live that day: Hermes Desktop's Hermes home with a commented config and Hermes's own record of
the plugin, Blackbox's node (marker, wallet and identity files, pid file) and reporter key, our
`blackbox` launcher beside Hermes Desktop's `hermes`, a Foreman-style node in ~/.dkg that must survive,
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
from plugins.blackbox.setup.platform import linux as platform_linux, macos as platform_macos, windows as platform_windows

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


@pytest.fixture(autouse=True)
def os_services(monkeypatch):
    """The login services are removed through ``setup/platform/<os>``; these plans are macOS's
    unless a test says otherwise (``_on``), whatever machine runs the suite."""
    monkeypatch.setattr(uninstall, "os_platform", platform_macos)


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


def _execute(plan: uninstall.UninstallPlan, *, dashboard_pids: tuple[int, ...] = (), admin_code: int = 0):
    calls: list[list[str]] = []

    def stop_dashboard(port: int) -> list[int]:
        calls.append(["stop-dashboard", str(port), str(plan.blackbox_home.exists())])
        return list(dashboard_pids)

    # run_as_admin is ALWAYS a fake here: a test must never reach a real sudo.
    report = uninstall.execute(plan, run=lambda cmd: calls.append(list(cmd)) or 0, stop_dashboard=stop_dashboard,
                               run_as_admin=lambda cmd: calls.append(["ADMIN", *cmd]) or admin_code)
    return calls, report


def test_the_plan_says_what_goes_and_what_stays(machine):
    lines = "\n".join(uninstall.describe(_plan(machine)))
    assert "remove Blackbox from the Hermes in" in lines and "blackbox-backup-" in lines
    assert str(machine / ".dkg") not in lines
    assert "Your Hermes itself, other DKG nodes and Docker's other containers are not touched." in lines


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


def test_linux_user_services_go_and_system_units_are_named_with_their_root_commands(machine, tmp_path, monkeypatch):
    monkeypatch.setattr(uninstall, "os_platform", platform_linux)
    user_units = machine / ".config" / "systemd" / "user"
    user_units.mkdir(parents=True)
    for unit in uninstall.SYSTEMD_UNITS:
        (user_units / unit).write_text("[Unit]", encoding="utf-8")
    system_unit = tmp_path / "etc" / "blackbox-dkg.service"
    system_unit.parent.mkdir()
    system_unit.write_text("[Unit]", encoding="utf-8")
    plan = dataclasses.replace(_plan(machine, system="Linux"), system_units=(system_unit,))
    calls, report = _execute(plan)
    assert not user_units.exists(), "emptied, the folders Blackbox's units lived in go too (KI-664)"
    assert ["systemctl", "--user", "disable", "--now", "blackbox-dkg.service"] in calls
    assert any(r.startswith("needs root: sudo systemctl disable --now blackbox-dkg.service") for r in report)
    assert system_unit.exists()


def test_windows_tasks_are_ended_and_deleted(machine, monkeypatch):
    monkeypatch.setattr(uninstall, "os_platform", platform_windows)
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
    monkeypatch.setattr(uninstall, "execute", lambda plan, **kwargs: executed.append(plan) or [])   # only the decision is tested
    args = argparse.Namespace(purge=False, keep_logs=False, dry_run=False, yes=False)
    assert uninstall.cmd_uninstall(args) == 0
    assert bool(executed) is removed


# ------------------------------------------------------------------ the system protection helper


def test_uninstall_removes_the_system_protection_helper_first(machine, tmp_path):
    helper = tmp_path / "blackbox-netd"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    plan = dataclasses.replace(_plan(machine), system_helper=helper)
    assert "remove the system protection helper" in "\n".join(uninstall.describe(plan))
    calls, report = _execute(plan)
    assert calls[0] == ["ADMIN", "sudo", str(helper), "uninstall"], "DNS goes back before anything else stops"
    assert report[0].startswith("removed the system protection helper")


def test_a_failed_helper_removal_says_how_to_finish_it(machine, tmp_path):
    helper = tmp_path / "blackbox-netd"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    _calls, report = _execute(dataclasses.replace(_plan(machine), system_helper=helper), admin_code=1)
    assert any(line.startswith("needs root:") and "uninstall" in line for line in report)


def test_no_helper_no_admin_step(machine):
    calls, _ = _execute(dataclasses.replace(_plan(machine), system_helper=None))
    assert not any(call and call[0] == "ADMIN" for call in calls)


def test_a_helper_the_person_cannot_see_is_still_removed_by_its_own_uninstall(machine, tmp_path):
    """E2E 2026-11-21: the helper's folder is root-only, so its program looks missing to the person.
    Uninstall must still run the helper's own uninstall (which puts DNS and the firewall back)."""
    unseen = tmp_path / "root-only" / "blackbox-netd"          # does not exist as the person sees it
    calls, report = _execute(dataclasses.replace(_plan(machine), system_helper=unseen))
    assert calls[0] == ["ADMIN", "sudo", str(unseen), "uninstall"]
    assert report[0].startswith("removed the system protection helper")


def test_the_manual_fallback_is_the_helpers_own_uninstall_never_a_bootout(machine, tmp_path):
    unseen = tmp_path / "root-only" / "blackbox-netd"
    _calls, report = _execute(dataclasses.replace(_plan(machine), system_helper=unseen), admin_code=1)
    text = "\n".join(report)
    assert f"sudo '{unseen}' uninstall" in text
    assert "bootout" not in text and "rm /Library/LaunchDaemons" not in text


# ------------------------------------------------------------------ coding agents' hooks and add-ons


def _claude_settings(machine: Path, blackbox_command: str) -> Path:
    settings = machine / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    mine = {"type": "command", "command": "echo my own hook"}
    ours = {"type": "command", "command": blackbox_command}
    settings.write_text(json.dumps({"theme": "dark", "hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [mine]}, {"matcher": "*", "hooks": [ours]}]}}), encoding="utf-8")
    return settings


def test_uninstall_takes_blackboxs_hooks_out_of_coding_agents_and_keeps_the_persons(machine):
    """E2E 2026-11-21: after uninstall every agent still ran ~/.hermes/blackbox/agent-hooks/runner.py,
    which uninstall had deleted. Only Blackbox's entries go; the person's own hook and settings stay."""
    from plugins.blackbox.agent_hooks.protect import config_edit
    runner = machine / ".hermes" / "blackbox" / "agent-hooks" / "runner.py"
    settings = _claude_settings(machine, f"/usr/bin/python3 {runner} claude-code pre_tool {config_edit.MARK}")
    plan = _plan(machine)
    assert "Claude Code" in "\n".join(uninstall.describe(plan))
    _calls, report = _execute(plan)
    data = json.loads(settings.read_text(encoding="utf-8"))
    commands = [hook["command"] for group in data.get("hooks", {}).get("PreToolUse", []) for hook in group["hooks"]]
    assert commands == ["echo my own hook"] and data["theme"] == "dark"
    assert any("took Blackbox's hooks out of Claude Code" in line for line in report)


def test_uninstall_removes_the_add_on_beside_the_plugin_and_no_other_plugin(machine):
    addon = machine / ".hermes" / "plugins" / "example_addon"
    addon.mkdir(parents=True)
    (addon / "__init__.py").write_text("", encoding="utf-8")
    (addon / "blackbox-addon.json").write_text('{"extends": "blackbox"}', encoding="utf-8")
    other = machine / ".hermes" / "plugins" / "someone_elses_plugin"
    other.mkdir(parents=True)
    (other / "__init__.py").write_text("", encoding="utf-8")
    plan = _plan(machine)
    assert f"remove the add-on {addon}" in "\n".join(uninstall.describe(plan))
    assert plan.addons == (addon,)
    _execute(plan)
    assert not addon.exists() and other.exists()


#: Each OS's key folder for the helper's pairing key (``kernel/system_helper/platform/<os>.py``).
KEY_FOLDERS = [("macos", "Library/Application Support/Blackbox/helper"), ("linux", ".config/blackbox/helper")]


def _key_folder(machine: Path, monkeypatch, system: str, relative: str) -> Path:
    """Uninstall as on *system*, whatever OS runs the test: that OS's key folder (PR #63's Linux CI
    pinned the macOS one, which a Linux runner's facade never names)."""
    import importlib
    from plugins.blackbox.kernel import system_helper
    places = importlib.import_module(f"plugins.blackbox.kernel.system_helper.platform.{system}")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(system_helper, "user_key_folder", places.user_key_folder)
    folder = machine / relative
    assert system_helper.user_key_folder() == folder
    return folder


@pytest.mark.parametrize("system, relative", KEY_FOLDERS)
def test_once_the_helper_is_gone_its_pairing_key_and_empty_folders_go_too(machine, tmp_path, monkeypatch, system, relative):
    """E2E recheck 2026-11-21: after uninstall ~/Library/Application Support/Blackbox/helper was
    left behind. The key goes once the helper is removed; a folder goes only when left empty."""
    folder = _key_folder(machine, monkeypatch, system, relative)
    folder.mkdir(parents=True)
    (folder / "plan.key").write_bytes(b"\x07" * 32)
    helper = tmp_path / "blackbox-netd"
    _calls, report = _execute(dataclasses.replace(_plan(machine), system_helper=helper))
    assert not folder.parent.exists(), "key, its folder and the empty Blackbox folder are gone"
    assert folder.parent.parent.is_dir(), "the folder above Blackbox's own is never removed"
    assert any("pairing key" in line for line in report)


@pytest.mark.parametrize("system, relative", KEY_FOLDERS)
def test_a_helper_that_could_not_be_removed_keeps_its_key_and_a_companion_apps_files_stay(machine, tmp_path, monkeypatch,
                                                                                          system, relative):
    folder = _key_folder(machine, monkeypatch, system, relative)
    folder.mkdir(parents=True)
    (folder / "plan.key").write_bytes(b"\x07" * 32)
    (folder.parent / "engine").write_text("a companion app's", encoding="utf-8")
    helper = tmp_path / "blackbox-netd"
    _execute(dataclasses.replace(_plan(machine), system_helper=helper), admin_code=1)
    assert (folder / "plan.key").exists(), "the still-installed helper needs its key"
    _execute(dataclasses.replace(_plan(machine), system_helper=helper))
    assert not folder.exists() and (folder.parent / "engine").exists(), "a non-empty folder is never removed"


@pytest.mark.skipif(sys.platform != "darwin" or not os.access("/usr/bin/sandbox-exec", os.X_OK),
                    reason="the agent sandbox runs on macOS")
def test_uninstall_clears_the_hermes_agents_execute_code_launcher(machine):
    """A Hermes process that still holds Blackbox's launcher setting after an uninstall starts
    execute_code's Python directly again: the launcher goes with Blackbox's home, and Hermes's hook
    point ignores a launcher that is not there (fail-open; round-3 execute_code finding)."""
    from plugins.blackbox.shields.files import mode as files_mode, sandbox
    from tools import code_kernel

    picked = files_mode.build(enabled=True, protected=("~/Documents",), sandboxed=("hermes",))
    sandbox.sync(picked)
    env = {"PATH": "/usr/bin:/bin"}
    assert sandbox.enter_hermes_process(picked, env).execute_code is True
    assert code_kernel.interpreter_launcher(env) != []
    _execute(_plan(machine))
    assert not (sandbox.hermes_shell_dir() / sandbox.HERMES_CODE_LAUNCHER).exists()
    assert code_kernel.interpreter_launcher(env) == []


def _system_unit(tmp_path):
    unit = tmp_path / "etc" / "blackbox-dkg.service"
    unit.parent.mkdir(exist_ok=True)
    unit.write_text("[Unit]", encoding="utf-8")
    return unit


def test_run_as_root_the_linux_system_units_are_stopped_and_removed(machine, tmp_path, monkeypatch):
    """KI-506: run as root, the root units in /etc/systemd/system were still left enabled."""
    unit = _system_unit(tmp_path)
    monkeypatch.setattr(uninstall, "os_platform", platform_linux)
    monkeypatch.setattr(platform_linux, "_is_root", lambda: True)
    plan = dataclasses.replace(_plan(machine, system="Linux"), system_units=(unit,))
    calls, report = _execute(plan)
    assert ["systemctl", "disable", "--now", "blackbox-dkg.service"] in calls and ["systemctl", "daemon-reload"] in calls
    assert not unit.exists() and "removed system service blackbox-dkg.service" in report
    assert not any(line.startswith("needs root") for line in report)


def test_a_dashboard_and_node_a_root_unit_still_supervises_are_never_stopped_by_pid(machine, tmp_path, monkeypatch):
    """KI-507: with the root units left (not root), stopping by pid only saw systemd start them again."""
    unit = _system_unit(tmp_path)
    monkeypatch.setattr(uninstall, "os_platform", platform_linux)
    monkeypatch.setattr(platform_linux, "_is_root", lambda: False)
    signalled = []
    monkeypatch.setattr(uninstall.os, "kill", lambda pid, sig: signalled.append(pid))
    plan = dataclasses.replace(_plan(machine, system="Linux"), system_units=(unit,))
    calls, report = _execute(plan, dashboard_pids=(4242,))
    assert not any(call[0] == "stop-dashboard" for call in calls) and signalled == []
    assert any(line.startswith("left running:") for line in report)


def _node_store(machine: Path, *, managed: bool) -> None:
    """The node's config.json as the installer writes it for a Blazegraph store (Linux round L2)."""
    dkg = machine / ".hermes" / "blackbox" / "node" / ".dkg"
    (dkg / "config.json").write_text(json.dumps({"name": "agent-blackbox", "store": {"backend": "blazegraph", "options": {
        "url": "http://127.0.0.1:9999/bigdata/namespace/agent-blackbox/sparql", "managedByDkg": managed, "timeout": 900000}}}),
        encoding="utf-8")


def test_the_blazegraph_store_the_node_made_is_named_and_removed_with_its_volume(machine, monkeypatch):
    """KI-676 (Linux round L2): after an uninstall the container dkg-blazegraph-agent-blackbox was
    still Up on 127.0.0.1:9999 (restart unless-stopped: back at every boot) with its data volume,
    and the plan never named it. Now it is named, removed with its volume and any too-small copy
    the provisioner kept — while the node is stopped, before its config goes."""
    from plugins.blackbox.setup import uninstall_data
    _node_store(machine, managed=True)
    monkeypatch.setattr(uninstall_data, "_docker_output",
                        lambda _cmd: "dkg-blazegraph-agent-blackbox\ndkg-blazegraph-agent-blackbox-pre-4g-1763\nsomeone-else\n")
    plan = _plan(machine, system="Linux")
    assert plan.store == uninstall_data.ManagedStore("dkg-blazegraph-agent-blackbox", "dkg-blazegraph-agent-blackbox-data")
    assert "remove its Blazegraph store: Docker container dkg-blazegraph-agent-blackbox and volume " \
           "dkg-blazegraph-agent-blackbox-data" in "\n".join(uninstall.describe(plan))
    calls, report = _execute(plan)
    docker = [call for call in calls if call[:1] == ["docker"]]
    assert docker == [["docker", "rm", "-f", "dkg-blazegraph-agent-blackbox"],
                      ["docker", "rm", "-f", "dkg-blazegraph-agent-blackbox-pre-4g-1763"],
                      ["docker", "volume", "rm", "-f", "dkg-blazegraph-agent-blackbox-data"]]
    assert any("removed the Blazegraph store" in line for line in report)


def test_an_operators_own_blazegraph_is_never_touched(machine):
    _node_store(machine, managed=False)
    plan = _plan(machine, system="Linux")
    assert plan.store is None
    calls, _ = _execute(plan)
    assert not [call for call in calls if call[:1] == ["docker"]]
