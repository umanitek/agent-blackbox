"""Sandbox permissions — the person's tool folders (``tool-folders``), defined once
(plugins/blackbox/kernel/persistence_places.user_path_folders; design "Sandbox permissions"
2026-11-23, build step 11, F2, LES-137; local-only).

Contracts (red on the base ed4152ceac: no user_path_folders, no way to close ~/.local/bin and the
other program folders the person owns — a program an agent left there ran outside the sandbox
the next time the person typed its name):
* the ONE list: the fixed tool folders and globs, plus every PATH folder inside home the person
  owns — never one outside home, one another user owns, or Blackbox's own launchers;
* the profile closes them to writes only while ``tool-folders`` is not allowed for that agent;
* on THIS Mac, a REAL Seatbelt run: blocked, a write into ~/.local/bin is refused and one into a
  project folder is not;
* the hook layer reads such a refusal as the tool-folders one, judged against the same list;
* the system protection helper's watch reads folders inside that list (parity, LES-137).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from plugins.blackbox.agent_hooks.protect import sandbox_errors
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import persistence_places
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.files.sandbox.permissions import Mode, Rule, Settings
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")
RUN_LATER = Path(__file__).resolve().parents[2] / "plugins/blackbox/helper/src/platform/macos/observe/run_later.rs"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    for folder in (".local/bin", "work", "tools/bin", "bb/agent-bin"):
        (real / folder).mkdir(parents=True)
    monkeypatch.setenv("PATH", f"{real}/bb/agent-bin:{real}/tools/bin:/usr/bin:/bin")
    return real


@pytest.fixture
def entry(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def test_the_one_list_holds_the_fixed_folders_and_the_owned_path_folders(home):
    folders, globs = persistence_places.user_path_folders(str(home), os.environ["PATH"], os.getuid(), exclude=(str(home / "bb"),))
    assert str(home / ".local/bin") in folders and str(home / "tools/bin") in folders
    assert str(home / "bb/agent-bin") not in folders and "/usr/bin" not in folders
    assert f"{home}/Library/Python/*/bin" in globs
    assert str(home / "tools/bin") not in persistence_places.user_path_folders(str(home), os.environ["PATH"], os.getuid() + 1)[0]


@pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile is rendered on macOS")
def test_the_profile_closes_them_only_while_tool_folders_is_not_allowed(home):
    blocked = permissions.allowances(Settings(rules=(Rule("tool-folders", Mode.BLOCK, permissions.Scope(agent="codex")),)), "codex")
    assert any(f'(subpath "{home}/.local/bin")' in line for line in macos_profile.permission_lines(blocked, str(home)))
    allowed = permissions.allowances(Settings(rules=(Rule("tool-folders", Mode.ALLOW),)), "codex")
    assert not any(".local/bin" in line for line in macos_profile.permission_lines(allowed, str(home)))


@REAL
def test_blocked_a_write_into_a_tool_folder_is_refused_and_a_project_is_not(home, entry):
    entry["agent_sandbox"] = {"permissions": [{"permission": "tool-folders", "mode": "block"}]}
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    profile = str(sandbox.layout.agent_profile("claude-code"))
    script = f"echo x > '{home}/.local/bin/evil'; echo tool=$?; echo x > '{home}/work/ok'; echo work=$?"
    done = subprocess.run([macos_profile.SANDBOX_EXEC, "-f", profile, "/bin/sh", "-c", script], capture_output=True, text=True,
                          timeout=30, check=False)
    assert "tool=1" in done.stdout and "work=0" in done.stdout


def test_the_hooks_read_that_refusal_as_tool_folders(home):
    found = sandbox_errors.refusals(f"zsh:1: operation not permitted: {home}/.local/bin/evil")
    assert [each.kind for each in found] == [sandbox_errors.TOOL_FOLDER] and sandbox_errors.counted(found)
    assert "tool folders" in sandbox_errors.note(found)


def test_the_helpers_watch_reads_folders_inside_the_one_list():
    watched = re.search(r"USER_PROGRAM_FOLDERS: &\[&str\] = &\[([^\]]*)\]", RUN_LATER.read_text(encoding="utf-8")).group(1)
    names = re.findall(r'"([^"]+)"', watched)
    fixed = [place.replace("{home}/", "") for place in persistence_places.USER_TOOL_FOLDERS]
    assert names and all(any(name == root or name.startswith(root + "/") for root in fixed) for name in names), names
