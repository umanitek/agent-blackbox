"""KI-589: setuid tools inside the agent sandbox (sandbox developer day, 2026-11-22).

macOS refuses to start a setuid program from any sandboxed process (``forbidden-exec-sugid``; no
Seatbelt rule lifts it). A sandboxed Claude Code saw ``operation not permitted: ps`` for every
``ps`` and the same for ``top`` and ``crontab -l``. Contracts:

* the launcher puts ``<agent-bin>/sandbox-tools`` first on the SANDBOXED PATH only: a ``ps`` copied
  without its setuid bit works there; the person's own PATH (``agent-bin``) gets no ``ps``;
* ``top`` / ``crontab`` (which need root to work at all) answer with why, not a bare OS error;
* the copies are made again when macOS (or its ``ps``) changes, never on every sync.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import changes, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox.platform import macos
from plugins.blackbox.shields.files.sandbox.platform.macos import tools as macos_tools

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos.SANDBOX_EXEC, os.X_OK) or not os.path.exists(macos.PS),
                          reason="a real Seatbelt sandbox needs macOS")
HONEST = "macOS doesn't allow setuid programs inside the agent sandbox; run it in your own terminal"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Documents" / "Vault").mkdir(parents=True)
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: {"mode": "audit", "shields": {}})
    changes.reset()
    yield real
    changes.reset()


def _mode():
    return files_mode.build(enabled=True, protected=("~/Documents/Vault",), sandboxed=("claude-code",))


def _agent(home, script: str) -> subprocess.CompletedProcess:
    """Runs a fake ``claude`` through Blackbox's launcher, the way the person's shell would."""
    fake = home / "fakebin"
    fake.mkdir(exist_ok=True)
    (fake / "claude").write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
    (fake / "claude").chmod(0o755)
    env = {**os.environ, "PATH": f"{sandbox.launcher_dir()}:{fake}:/usr/bin:/bin"}
    env.pop("BLACKBOX_AGENT_SANDBOX", None)
    return subprocess.run(["claude"], capture_output=True, text=True, timeout=30, env=env, check=False)


@REAL
def test_ps_works_inside_the_sandbox_from_a_copy_without_the_setuid_bit(home):
    sandbox.sync(_mode())
    done = _agent(home, 'ps -p $$ -o pid= >/dev/null; echo ps=$?; /bin/ps -p $$ >/dev/null 2>&1; echo absolute=$?')
    words = done.stdout.split()
    assert "ps=0" in words and "absolute=0" not in words, (done.stdout, done.stderr)   # /bin/ps itself stays refused
    copy = sandbox.launcher_dir() / macos.TOOLS_FOLDER / "ps"
    assert not copy.stat().st_mode & (stat.S_ISUID | stat.S_ISGID)
    assert not (sandbox.launcher_dir() / "ps").exists()      # the person's own PATH keeps the real ps


@REAL
def test_a_setuid_tool_that_needs_root_says_why_instead_of_a_bare_os_error(home):
    sandbox.sync(_mode())
    done = _agent(home, "top -l 1 >/dev/null; echo top=$?; crontab -l; echo crontab=$?")
    assert "top=126" in done.stdout.split() and "crontab=126" in done.stdout.split(), (done.stdout, done.stderr)
    assert f"Blackbox's sandbox refused this (top): {HONEST}" in done.stderr
    assert f"Blackbox's sandbox refused this (crontab): {HONEST}" in done.stderr


@REAL
def test_the_tools_are_made_again_only_when_macos_changes(home):
    sandbox.sync(_mode())
    launchers = str(sandbox.launcher_dir())
    assert macos.refresh_tools(launchers) is False                 # same macOS: nothing written
    marker = sandbox.launcher_dir() / macos.TOOLS_FOLDER / macos_tools._TOOLS_STAMP
    marker.write_text("26.0 an older macOS\n", encoding="utf-8")
    assert macos.refresh_tools(launchers) is True
    assert marker.read_text(encoding="utf-8") == macos_tools._stamp()


def test_the_hermes_shells_put_the_tools_first_on_the_sandboxed_path_only():
    shim = macos.shell_shim("bash", "/bb/sandbox/hermes-shell", "/bb/sandbox/agents.sb", "/bb/sandbox/canary", "/bb/agent-bin")
    before_exec = shim.split("exec /usr/bin/sandbox-exec")[0]
    assert "tools='/bb/agent-bin/sandbox-tools'" in before_exec and 'PATH="$tools:$PATH"' in before_exec
    outside = shim.split("then exec \"$real\"")[0]
    assert "sandbox-tools" not in outside
