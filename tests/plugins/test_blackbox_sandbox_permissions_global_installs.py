"""Sandbox permissions — global installs through Blackbox (``global-installs``, F1; ``tool-folders``
blocked by default from here, F2) (plugins/blackbox/shields/files/sandbox/packages/managers.py,
platform/macos/shims.manager_shims; design "Sandbox permissions" 2026-11-23, build step 12, local-only).

Contracts (red on the base ed4152ceac: no install broker, no package-manager shims):
* each manager's global install is accepted as names only with its one global flag, and run as a
  FIXED argv; a URL, path, git source, registry/index option or a local install is refused;
* the shim sends a global install to the broker and runs everything else (``npm install`` in a
  project, ``pip install`` without ``--user``, ``cargo build``) as the real program;
* the broker decides by the ``global-installs`` permission (block → 403, ask → a request and 423),
  checks each name against the threat graph, and runs the fixed argv with a clean environment;
* the client says, when Blackbox can not be reached, to run the manager's own command in the
  person's terminal.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files.sandbox import packages
from plugins.blackbox.shields.files.sandbox.packages import client, jobs, managers
from plugins.blackbox.shields.files.sandbox.packages.request import Refused
from plugins.blackbox.shields.files.sandbox.permissions import requests
from plugins.blackbox.shields.files.sandbox.platform.macos import shims
from plugins.blackbox.shields.shield_api import ShieldApiError, ShieldContext

MAC = pytest.mark.skipif(sys.platform != "darwin", reason="the shims are macOS's")


@pytest.fixture(autouse=True)
def setting(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    jobs.reset()
    requests.reset()
    yield state
    jobs.reset()
    requests.reset()


@pytest.mark.parametrize("manager, argv, runs", [
    ("npm", ["install", "-g", "typescript"], ["install", "--global", "typescript"]),
    ("npm", ["i", "--global", "@scope/tool@1.2.3"], ["install", "--global", "@scope/tool@1.2.3"]),
    ("pipx", ["install", "ruff"], ["install", "ruff"]),
    ("pip", ["install", "--user", "-U", "httpie"], ["install", "--user", "--upgrade", "httpie"]),
    ("cargo", ["install", "ripgrep"], ["install", "ripgrep"]),
    ("gem", ["install", "bundler"], ["install", "--user-install", "bundler"]),
    ("uv", ["tool", "install", "ruff"], ["tool", "install", "ruff"]),
])
def test_a_global_install_is_names_only_and_a_fixed_argv(manager, argv, runs):
    assert managers.parse(manager, argv).words() == runs


@pytest.mark.parametrize("manager, argv", [
    ("npm", ["install", "typescript"]),                         # local, not global
    ("npm", ["install", "-g", "https://evil.invalid/x.tgz"]),
    ("npm", ["install", "-g", "--registry", "https://evil.invalid", "x"]),
    ("npm", ["install", "-g", "github:someone/x"]),
    ("pipx", ["install", "--index-url", "https://evil.invalid", "x"]),
    ("pipx", ["install", "git+https://x/y.git"]),
    ("pip", ["install", "x"]),                                  # not --user
    ("pip", ["install", "--user", "./local"]),
    ("cargo", ["install", "--git", "https://x/y", "z"]),
    ("cargo", ["build"]),
    ("uv", ["pip", "install", "x"]),
    ("brew", ["install", "x"]),
])
def test_anything_else_is_refused(manager, argv):
    with pytest.raises(Refused):
        managers.parse(manager, argv)


def _shim(tmp_path, program):
    tools = tmp_path / "tools"
    real = tmp_path / "real"
    tools.mkdir(exist_ok=True)
    real.mkdir(exist_ok=True)
    python = tmp_path / "fake-python"
    python.write_text('#!/bin/sh\necho "broker $*"\n', encoding="utf-8")
    python.chmod(0o755)
    text = shims.manager_shims(str(tools), str(python), "http://127.0.0.1:9700")[program]
    (tools / program).write_text(text, encoding="utf-8")
    (tools / program).chmod(0o755)
    (real / program).write_text('#!/bin/sh\necho "real $*"\n', encoding="utf-8")
    (real / program).chmod(0o755)
    return tools, real


@MAC
@pytest.mark.parametrize("program, argv, routed", [
    ("npm", ["install", "-g", "typescript"], "broker"), ("npm", ["install"], "real"), ("npm", ["run", "build", "-g"], "real"),
    ("pip3", ["install", "--user", "x"], "broker"), ("pip3", ["install", "x"], "real"),
    ("cargo", ["install", "rg"], "broker"), ("cargo", ["build"], "real"),
    ("uv", ["tool", "install", "ruff"], "broker"), ("uv", ["run", "x"], "real"),
])
def test_the_shim_sends_only_a_global_install_to_the_broker(tmp_path, program, argv, routed):
    tools, real = _shim(tmp_path, program)
    done = subprocess.run([str(tools / program), *argv], capture_output=True, text=True, timeout=30, check=False,
                          env={**os.environ, "PATH": f"{tools}:{real}:/usr/bin:/bin"})
    assert done.stdout.split()[0] == routed, done.stdout + done.stderr
    if routed == "broker":
        assert "--manager" in done.stdout


def _context():
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                         tool_call_verdict=lambda tool, args: {"decision": "block" if "evil" in args["command"] else "", "findings": []})


def test_the_broker_decides_checks_and_runs_the_fixed_argv(setting, monkeypatch, tmp_path):
    ran, finished = [], threading.Event()

    def spawn(command, env, cwd):
        ran.append((command, env))
        return subprocess.Popen([sys.executable, "-c", "print('added 1 package')"], stdout=subprocess.PIPE, text=True)

    monkeypatch.setattr(jobs.platform, "spawn_brew", spawn)
    monkeypatch.setattr(packages, "manager_path", lambda program: f"/opt/homebrew/bin/{program}")
    monkeypatch.setattr(packages, "_record", lambda job: finished.set())
    started = packages.API_WRITES["install"](_context(), {"manager": "npm", "argv": ["install", "-g", "typescript"]})
    assert finished.wait(30) and started["command"] == "npm install --global typescript"
    command, env = ran[0]
    assert command == ["/opt/homebrew/bin/npm", "install", "--global", "typescript"] and set(env) <= {"HOME", "USER", "LOGNAME", "PATH", "LANG", "TMPDIR"}
    with pytest.raises(ShieldApiError) as listed:
        packages.API_WRITES["install"](_context(), {"manager": "npm", "argv": ["install", "-g", "evil-pkg"]})
    assert listed.value.status == 403 and "evil-pkg" in listed.value.message
    setting["agent_sandbox"] = {"permissions": [{"permission": "global-installs", "mode": "block"}]}
    with pytest.raises(ShieldApiError) as blocked:
        packages.API_WRITES["install"](_context(), {"manager": "npm", "argv": ["install", "-g", "typescript"]})
    assert blocked.value.status == 403
    setting["agent_sandbox"] = {"permissions": [{"permission": "global-installs", "mode": "ask"}]}
    with pytest.raises(ShieldApiError) as waiting:
        packages.API_WRITES["install"](_context(), {"manager": "pipx", "argv": ["install", "ruff"]})
    assert waiting.value.status == packages.WAITING and requests.pending()[0].what == "pipx install ruff"


def test_an_unreachable_broker_names_the_managers_own_command(capsys):
    assert client.main(["brew-client.py", "http://127.0.0.1:9", "--manager", "npm", "install", "-g", "x"]) == 1
    assert "run `npm install -g x` in your own terminal" in capsys.readouterr().err
