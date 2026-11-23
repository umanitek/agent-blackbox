"""Sandbox permissions — one profile per agent, the never-list last
(plugins/blackbox/shields/files/sandbox/profiles.py, platform/macos/profile.py; design "Sandbox
permissions" 2026-11-23, build step 5, local-only).

Contracts (red on the base ed4152ceac: one shared agents.sb, no per-agent profile, no never mark):
* every rendered profile ends with the never-list: everything after its mark is exactly the
  shared policy's lines, and every permission line comes before it (Seatbelt: a later rule wins);
* the catalogue defaults add only the lines of what they do not allow (Docker asks: its sockets);
* a folder rule adds exactly its lines (none: no read, no write; read: no write);
* sync writes each sandboxed agent's own profile, removes the profile of an agent taken out, and
  each launcher / Hermes shell starts its agent in ITS profile;
* on THIS Mac, a REAL Seatbelt run: a folder kept from Codex only is refused to Codex's profile and
  readable in Claude Code's.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions, profiles
from plugins.blackbox.shields.files.sandbox.permissions import Access, FolderRule, Scope, Settings
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")
MAC = pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile is rendered on macOS")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Documents" / "Vault").mkdir(parents=True)
    (real / "clients").mkdir()
    (real / "clients" / "deal.txt").write_text("deal", encoding="utf-8")
    return real


@pytest.fixture
def entry(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def _mode(sandboxed=("claude-code",)):
    return files_mode.build(enabled=True, protected=("~/Documents/Vault",), sandboxed=tuple(sandboxed))


def _split(text: str) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    mark = lines.index(macos_profile.NEVER_MARK)
    return lines[:mark], lines[mark + 1:]


@MAC
def test_the_never_list_is_the_tail_and_every_permission_line_is_above_it(home, entry):
    places = sandbox.policy(_mode())
    hidden = permissions.Allowances(hidden=(str(home / "clients"),), read_only=(str(home / "Documents"),))
    head, tail = _split(profiles.render_signed(places, hidden))
    assert "\n".join(tail) == "\n".join(macos_profile._never(places))
    assert "\n".join(macos_profile.permission_lines(hidden)) in "\n".join(head)
    assert all(str(home / "clients") not in line for line in tail)


@MAC
def test_the_catalogue_defaults_add_only_the_lines_of_what_is_not_allowed(home, entry):
    """Step 10 changed this: Docker asks by default (F4), so its sockets are closed by default."""
    assert macos_profile.permission_lines(permissions.allowances(Settings(), "claude-code"), str(home)) == \
        macos_profile._docker_lines(str(home))


@MAC
def test_each_folder_rule_adds_exactly_its_lines(home):
    keep_out = permissions.allowances(Settings(folders=(FolderRule("~/clients", Access.NONE),)))
    read_only = permissions.allowances(Settings(folders=(FolderRule("~/clients", Access.READ),)))
    docker = macos_profile._docker_lines(str(home))
    assert macos_profile.permission_lines(keep_out, str(home)) == docker + [f'(deny file-read* file-write* file-link\n  (subpath "{home}/clients"))']
    assert macos_profile.permission_lines(read_only, str(home)) == docker + [f'(deny file-write*\n  (subpath "{home}/clients"))']


@MAC
def test_sync_writes_each_agents_profile_and_its_launcher_uses_it(home, entry):
    sandbox.sync(_mode(("claude-code", "codex", "hermes")))
    folder = sandbox.layout.profiles_dir()
    assert sorted(path.name for path in folder.iterdir()) == ["claude-code.sb", "codex.sb", "hermes.sb"]
    assert f"profile='{folder / 'claude-code.sb'}'" in (sandbox.launcher_dir() / "claude").read_text(encoding="utf-8")
    assert f"profile='{folder / 'hermes.sb'}'" in (sandbox.hermes_shell_dir() / "bash").read_text(encoding="utf-8")
    sandbox.sync(_mode(("claude-code",)))
    assert sorted(path.name for path in folder.iterdir()) == ["claude-code.sb"]


@REAL
def test_a_folder_kept_from_one_agent_is_refused_to_it_alone(home, entry):
    entry["agent_sandbox"] = {"folders": [{"path": "~/clients", "access": "none", "agent": "codex"}]}
    sandbox.sync(_mode(("claude-code", "codex")))
    target = str(home / "clients" / "deal.txt")

    def read(agent: str) -> subprocess.CompletedProcess:
        return subprocess.run([macos_profile.SANDBOX_EXEC, "-f", str(sandbox.layout.agent_profile(agent)), "/bin/cat", target],
                              capture_output=True, text=True, timeout=30, check=False)

    assert read("claude-code").stdout == "deal"
    refused = read("codex")
    assert refused.returncode != 0 and "deal" not in refused.stdout


def test_a_scope_for_another_agent_does_not_reach_this_one(home):
    rules = Settings(folders=(FolderRule("~/clients", Access.NONE, Scope(agent="codex")),))
    assert permissions.allowances(rules, "claude-code").hidden == ()
    assert permissions.allowances(rules, "codex").hidden == (str(home / "clients"),)
