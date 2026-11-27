"""Linux's pages say what Linux does — no macOS controls, the right helper advice, no notification
claimed on a server (KI-660, KI-661, KI-662; Linux round L1, core eb71c1d03c, Ubuntu 24.04).

* KI-660: File Shield's "Sandbox permissions" offered macOS's whole catalogue with live Block /
  Ask / Allow buttons (and "ssh into this Mac … probed on macOS 27.2") where no sandbox runs.
* KI-661: every Network Shield card said "… or from a companion app" — Linux has none, and the
  Linux installer could not install the helper at all.
* KI-662: with notify-send installed on a server, the notifier status said "shown by this
  desktop's own notifier" while every send was "not shown".
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

from plugins.blackbox.shields.files import api as files_api
from plugins.blackbox.shields.files import sandbox
from plugins.blackbox.shields.files.sandbox import permissions

REPO = Path(__file__).resolve().parents[2]


def test_where_agents_can_not_be_sandboxed_no_permission_is_offered_as_a_control(monkeypatch):
    why = "Agents can not be sandboxed here: the launcher is not installed. Blackbox's hooks still protect your files."
    monkeypatch.setattr(sandbox, "unavailable", lambda: why)
    monkeypatch.setattr(sandbox, "stale_runs", lambda runs: [])
    view = files_api.permissions_view(None, {})
    sandbox_rows = [each for each in view["permissions"] if each["route"] != "hook"]
    assert sandbox_rows and all(each["controllable"] is False and each["note"] == why for each in sandbox_rows)
    assert view["never"] == [] and view["not_controllable"] == [] and view["sandbox_unavailable"] == why
    assert not any("this Mac" in str(each) for each in view["never"])


def test_where_agents_can_not_be_sandboxed_the_hook_permissions_stay_settable(monkeypatch):
    """The hooks, not the sandbox, enforce startup items, shell startup files, sudo writes, unnamed
    publishers and vulnerable packages: a machine with no sandbox still offers them (engine build
    2026-11-27)."""
    monkeypatch.setattr(sandbox, "unavailable", lambda: "no sandbox here")
    monkeypatch.setattr(sandbox, "stale_runs", lambda runs: [])
    view = files_api.permissions_view(None, {})
    hook_rows = {each["id"]: each for each in view["permissions"] if each["route"] == "hook"}
    assert set(hook_rows) == {"startup-items", "shell-startup", "root-writes", "unnamed-publisher", "vulnerable-packages"}
    assert all(each["controllable"] and each["note"] != "no sandbox here" for each in hook_rows.values())


def test_where_the_sandbox_runs_the_catalogue_is_unchanged(monkeypatch):
    monkeypatch.setattr(sandbox, "unavailable", lambda: None)
    monkeypatch.setattr(sandbox, "stale_runs", lambda runs: [])
    view = files_api.permissions_view(None, {})
    assert view["sandbox_unavailable"] == "" and any(each["controllable"] for each in view["permissions"])
    assert view == {**permissions.view(sandbox.chosen(files_api.mode_module.current())), "restart_needed": []}


def _load(relative: str):
    spec = importlib.util.spec_from_file_location(relative.replace("/", "_"), REPO / "plugins/blackbox" / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_linux_helper_advice_names_the_installer_not_a_companion_app():
    linux = _load("kernel/system_helper/platform/linux.py")
    assert "--system-protection" in linux.INSTALL_HOW and "companion" not in linux.INSTALL_HOW


def test_a_server_with_notify_send_but_no_notifier_says_nothing_is_shown(monkeypatch, tmp_path):
    from plugins.blackbox.notify.platform import linux as notifier   # importable on any OS (no OS calls at import)
    monkeypatch.setattr(notifier, "_tool", lambda: "/usr/bin/notify-send")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    monkeypatch.setattr(notifier.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "busctl" else None)
    answers = {"owner": "b false\n"}
    monkeypatch.setattr(notifier.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 0, answers["owner"], ""))
    server = notifier.status()
    assert server.available is False and "No desktop notifier" in server.detail
    assert notifier.send("t", "b", "info", "x").outcome == "not-shown"
    answers["owner"] = "b true\n"
    desktop = notifier.status()
    assert desktop.available is True and desktop.permission == "authorized"
