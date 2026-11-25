"""The sandbox launcher hands the agent its arguments exactly, however they are quoted (KI-601).

Security round 4 (REAL, Codex 0.171.0 gpt-5-nano through ``agent-bin/codex``): every command the
model sent as ``bash -lc '<script>'`` ran as ``/bin/zsh -lc bash`` — the script lost, output empty,
exit 0 — and Blackbox's hook saw only ``bash``; started by full path, the same prompts ran. This
proves the LAUNCHER's half with the real Seatbelt sandbox: every argument reaches the real program
byte for byte (spaces, quotes, ``$``, backticks, backslashes, an empty word, a newline, Codex's own
``-lc`` form), and its working folder and environment are kept. The loss therefore happens inside
Codex under the sandbox — the round-5 VM run records Codex's shell snapshot to find where.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from plugins.blackbox.shields.files import changes, mode as files_mode, sandbox

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access("/usr/bin/sandbox-exec", os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")
TRICKY = ["exec", "--json", "bash -lc 'python3 r.py Doc Sec'", "a  b", "it's", '"quoted"', "$HOME", "`id`", "back\\slash", "",
          "-lc", "multi\nline", "*", "--", "; rm -rf x", "émoji ✓"]


@pytest.fixture
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    changes.reset()
    yield real
    changes.reset()


@REAL
def test_the_launcher_hands_the_real_program_every_argument_exactly(home):
    sandbox.sync(files_mode.build(enabled=True, protected=("~/Documents/Vault",), sandboxed=("codex",)))
    fake = home / "real-bin"
    fake.mkdir()
    (fake / "codex").write_text("#!/bin/sh\npwd\nprintf '%s\\n' \"$BLACKBOX_AGENT_SANDBOX\"\nfor a in \"$@\"; do printf '%s\\0' \"$a\"; done\n",
                                encoding="utf-8")
    (fake / "codex").chmod(0o755)
    work = home / "project"
    work.mkdir()
    done = subprocess.run([str(sandbox.launcher_dir() / "codex"), *TRICKY], capture_output=True, timeout=30, check=False, cwd=work,
                          env={"PATH": f"{sandbox.launcher_dir()}:{fake}:/usr/bin:/bin", "HOME": str(home)})
    assert done.returncode == 0, done.stderr
    folder, inside, rest = done.stdout.split(b"\n", 2)
    assert folder.decode() == str(work) and inside == b"1"   # its folder kept, and inside the sandbox
    assert [word.decode() for word in rest.split(b"\0")[:-1]] == TRICKY
