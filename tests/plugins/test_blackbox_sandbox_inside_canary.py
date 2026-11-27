"""Agent sandbox — "already inside" is proven by the canary, never by a variable or by a canary
someone made unreadable (plugins/blackbox/shields/files/sandbox/platform/posix_scripts.py
``inside_test``, sandbox/__init__.py ``proven``; independent review 2026-11-26, findings 3 and 10;
LES-154).

Contracts (red on the base 30b94edf83):
* the launchers, the Hermes shells and the ``execute_code`` launcher sandbox the program even when
  ``BLACKBOX_AGENT_SANDBOX=1`` is set — an agent can set it (``launchctl setenv``) — and run it as
  it is only when the canary is refused the way a sandbox refuses it;
* a canary made unreadable outside a sandbox (``chmod 000``) proves nothing, in the shell and in
  Python; a Seatbelt-style refusal (EPERM) of a real canary file does.

The scripts are RUN in a temp folder with a fake runner and a fake canary reader — no real sandbox.
"""

from __future__ import annotations

import errno
import os
import subprocess

import pytest

from plugins.blackbox.shields.files import sandbox
from plugins.blackbox.shields.files.sandbox.platform import posix_scripts

SUFFIXES = posix_scripts.Suffixes(".sb", ".once.sb")
SEATBELT_READER = '#!/bin/sh\necho "cat: $2: Operation not permitted" >&2\nexit 1\n'


@pytest.fixture()
def bench(tmp_path):
    (tmp_path / "bin").mkdir()
    real = tmp_path / "bin" / "agent"
    real.write_text("#!/bin/sh\necho real\n", encoding="utf-8")
    runner = tmp_path / "runner"
    runner.write_text("#!/bin/sh\necho sandboxed\n", encoding="utf-8")
    reader = tmp_path / "seatbelt-cat"
    reader.write_text(SEATBELT_READER, encoding="utf-8")
    for program in (real, runner, reader):
        program.chmod(0o755)
    (tmp_path / "sandbox").mkdir()
    canary = tmp_path / "sandbox" / "canary"
    canary.write_text("canary\n", encoding="utf-8")
    canary.chmod(0o644)
    profile = tmp_path / "agents.sb"
    profile.write_text("(version 1)\n", encoding="utf-8")
    return tmp_path


def _scripts(bench):
    here, profile, canary = str(bench / "launchers"), str(bench / "agents.sb"), str(bench / "sandbox" / "canary")
    runner = posix_scripts.quote_shell(str(bench / "runner"))
    return {"launcher": posix_scripts.launcher_script("agent", here, profile, runner, "", SUFFIXES, canary),
            "shell": posix_scripts.shell_shim("agent", here, profile, runner, "", SUFFIXES, canary),
            "execute_code": posix_scripts.command_shim(profile, runner, "", SUFFIXES, canary)}


def _run(bench, name, text, extra_env):
    script = bench / f"{name}.sh"
    script.write_text(text, encoding="utf-8")
    script.chmod(0o755)
    argv = [str(script)] + ([str(bench / "bin" / "agent")] if name == "execute_code" else [])
    env = {"PATH": f"{bench / 'bin'}:/usr/bin:/bin", "HOME": str(bench), **extra_env}
    done = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=env, cwd=str(bench), check=False)
    return done.stdout.strip()


@pytest.mark.parametrize("name", ["launcher", "shell", "execute_code"])
def test_a_variable_never_takes_a_program_out_of_the_sandbox(bench, name):
    text = _scripts(bench)[name]
    assert _run(bench, name, text, {"BLACKBOX_AGENT_SANDBOX": "1"}) == "sandboxed"


@pytest.mark.parametrize("name", ["launcher", "shell", "execute_code"])
def test_a_canary_made_unreadable_outside_proves_nothing(bench, name):
    (bench / "sandbox" / "canary").chmod(0o000)
    if os.access(bench / "sandbox" / "canary", os.R_OK):
        pytest.skip("this user reads any file (root)")
    assert _run(bench, name, _scripts(bench)[name], {"BLACKBOX_AGENT_SANDBOX": "1"}) == "sandboxed"


@pytest.mark.parametrize("name", ["launcher", "shell", "execute_code"])
def test_a_sandbox_refusal_of_the_canary_runs_the_program_as_it_is(bench, name, monkeypatch):
    monkeypatch.setattr(posix_scripts, "CANARY_READER", posix_scripts.quote_shell(str(bench / "seatbelt-cat")))
    assert _run(bench, name, _scripts(bench)[name], {}) == "real"


def test_python_counts_only_a_refusal_the_canarys_own_permissions_can_not_explain(bench, monkeypatch):
    canary = bench / "sandbox" / "canary"
    assert sandbox.proven(canary) is False
    canary.chmod(0o000)
    if os.access(canary, os.R_OK):
        pytest.skip("this user reads any file (root)")
    assert sandbox.proven(canary) is False   # chmod 000 outside a sandbox: EACCES on its own device
    canary.chmod(0o644)

    def seatbelt(path, *args, **kwargs):
        raise PermissionError(errno.EPERM, "Operation not permitted", str(path))
    monkeypatch.setattr(sandbox, "open", seatbelt, raising=False)
    assert sandbox.proven(canary) is True
