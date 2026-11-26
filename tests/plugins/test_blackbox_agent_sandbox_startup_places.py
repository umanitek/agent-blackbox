"""Inside the agent sandbox nothing can be left to start by itself or to run later outside it.

Private security finding ``2026-11-23-agent-sandbox-launchagents-opt-homebrew-`` (security round 4,
High, kernel-real probe with the installed agents.sb): writable from inside were
``~/Library/LaunchAgents/`` (launchd loads an agent-written job at the next login, outside the
sandbox), ``/opt/homebrew/bin/``, ``/opt/homebrew/Cellar/<f>/`` and ``/opt/homebrew/Library/Taps/``
(``brew tap someone/evil-tap`` began cloning into Taps; a program dropped in brew's bin runs outside
the sandbox the next time the person types its name). Each place is proven here with the REAL
Seatbelt sandbox in a temporary home and a temporary Homebrew prefix (never the real one).
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox.shields.files import changes, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import platform
from plugins.blackbox.kernel import persistence_places as places_mod

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access("/usr/bin/sandbox-exec", os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    brew = real / "brew"
    (brew / "bin").mkdir(parents=True)
    (brew / "bin" / "brew").write_text("#!/bin/sh\n", encoding="utf-8")
    for folder in ("Cellar/jq/1.8", "Library/Taps/homebrew", "var/log", "opt"):
        (brew / folder).mkdir(parents=True)
    monkeypatch.setattr(platform, "startup_places", lambda home_folder: places_mod.startup_places(home_folder, (str(brew),)))
    (real / ".ssh").mkdir()
    (real / "Library" / "Preferences").mkdir(parents=True)
    changes.reset()
    yield real
    changes.reset()


def _run(script: str) -> dict[str, str]:
    done = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(sandbox.profile_path()), "/bin/sh", "-c", script],
                          capture_output=True, text=True, timeout=30, check=False)
    return dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)


def _sync():
    sandbox.sync(files_mode.build(enabled=True, protected=("~/Documents/Vault",), sandboxed=("claude-code",)))


@REAL
def test_no_launchd_job_login_item_or_ssh_login_file_can_be_left_from_inside(home):
    _sync()
    lines = _run(f"""
mkdir -p '{home}/Library/LaunchAgents' 2>/dev/null; echo agents_dir=$?
echo '<plist/>' > '{home}/Library/LaunchAgents/com.evil.plist' 2>/dev/null; echo agent=$?
mkdir -p '{home}/Library/Application Support/com.apple.backgroundtaskmanagementagent' 2>/dev/null; echo btm=$?
echo x > '{home}/Library/Preferences/com.apple.loginitems.plist' 2>/dev/null; echo loginitems=$?
echo x > '{home}/Library/Preferences/com.apple.loginwindow.plist' 2>/dev/null; echo loginwindow=$?
echo x > '{home}/Library/Preferences/com.example.app.plist' 2>/dev/null; echo other_pref=$?
echo 'ssh-ed25519 AAAA x' >> '{home}/.ssh/authorized_keys' 2>/dev/null; echo authorized=$?
echo 'touch /tmp/x' > '{home}/.ssh/rc' 2>/dev/null; echo rc=$?
echo x > '{home}/.ssh/known_hosts' 2>/dev/null; echo known_hosts=$?
""")
    assert lines == {"agents_dir": "1", "agent": "1", "btm": "1", "loginitems": "1", "loginwindow": "1", "other_pref": "0",
                     "authorized": "1", "rc": "1", "known_hosts": "0"}, lines
    assert not (home / "Library" / "LaunchAgents").exists() and not (home / ".ssh" / "authorized_keys").exists()


@REAL
def test_homebrews_prefix_is_closed_but_its_var_folder_stays_writable(home):
    _sync()
    brew = home / "brew"
    lines = _run(f"""
echo x > '{brew}/bin/git' 2>/dev/null; echo bin=$?
mkdir '{brew}/Library/Taps/someone' 2>/dev/null; echo tap=$?
echo x > '{brew}/Cellar/jq/1.8/jq' 2>/dev/null; echo cellar=$?
ln -s /tmp '{brew}/opt/evil' 2>/dev/null; echo opt=$?
mkdir '{brew}/sbin' 2>/dev/null; echo sbin=$?
echo x > '{brew}/var/log/service.log' 2>/dev/null; echo var=$?
""")
    assert lines == {"bin": "1", "tap": "1", "cellar": "1", "opt": "1", "sbin": "1", "var": "0"}, lines
    assert not (brew / "bin" / "git").exists() and not (brew / "Library" / "Taps" / "someone").exists()


@REAL
def test_the_tool_folders_are_closed_by_default_and_open_only_when_allowed(home, monkeypatch):
    """Sandbox permissions, F2 (2026-11-23): ``~/.local/bin`` is closed while ``tool-folders`` is
    blocked — the default since the global-installs broker ships — and open once it is allowed."""
    (home / ".local" / "bin").mkdir(parents=True)
    _sync()
    assert _run(f"echo x > '{home}/.local/bin/tool'; echo local_bin=$?") == {"local_bin": "1"}
    from plugins.blackbox.kernel import config as config_mod
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: {"agent_sandbox": {"permissions": [{"permission": "tool-folders", "mode": "allow"}]}})
    _sync()
    assert _run(f"echo x > '{home}/.local/bin/tool'; echo local_bin=$?") == {"local_bin": "0"}


def test_homebrews_folders_are_named_only_where_homebrew_is_installed(tmp_path):
    assert places_mod.homebrew_folders((str(tmp_path / "none"),)) == []
    (tmp_path / "hb" / "Homebrew").mkdir(parents=True)
    named = places_mod.homebrew_folders((str(tmp_path / "hb"),))
    assert str(tmp_path / "hb" / "bin") in named and str(tmp_path / "hb" / "Library") in named
    assert str(tmp_path / "hb" / "var") not in named
