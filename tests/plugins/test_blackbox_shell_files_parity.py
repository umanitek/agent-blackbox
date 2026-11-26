"""The OpenClaw bridge reads a shell command's files exactly as the Python does (2026-11-20).

Seen on a real OpenClaw agent: `exec cat ~/.ssh/id_rsa` and `exec cat ~/.config/solana/id.json`
ran in Block mode while Hermes blocked the same commands on the same machine — the bridge
applied its path rules to file tools only. `integrations/openclaw/src/shellFiles.ts` is now a
copy of `detection/paths/shell_files.py`, held to it by `tests/parity/shell_files_fixtures.json`:
this file checks the Python still produces the fixture (so a change to shell_files.py forces a
regenerate and a look at the copy) and runs the TypeScript against it through Node (LES-029).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "parity" / "shell_files_fixtures.json"
TS_PARITY = REPO / "integrations" / "openclaw" / "test" / "shell-files-parity.mjs"
#: Node runs a .ts file as it is (type stripping, no flag) from this version on.
NODE_RUNS_TYPESCRIPT = (22, 18)

sys.path.insert(0, str(REPO / "tests" / "parity"))


def test_the_fixture_is_what_the_python_produces_now():
    import generate_shell_files

    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert recorded == json.loads(json.dumps(generate_shell_files.fixture)), \
        "shell_files.py changed: run tests/parity/generate_shell_files.py, then update integrations/openclaw/src/shellFiles.ts"
    assert len(recorded["commands"]) >= 70


def test_the_fixture_covers_every_kind_of_command():
    commands = [case["command"] for case in json.loads(FIXTURE.read_text(encoding="utf-8"))["commands"]]
    for needle in ("cat ", "cp ", "tar ", "zip ", "find ", "xargs", "python3 -c", "node -e", "<<", "cd ", "C:\\", "grep -r"):
        assert any(needle in command for command in commands), needle


def test_the_typescript_copy_answers_the_same(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed here (CI has it)")
    version = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30, check=False).stdout
    found = re.match(r"v(\d+)\.(\d+)", version.strip())
    if not found or (int(found.group(1)), int(found.group(2))) < NODE_RUNS_TYPESCRIPT:
        pytest.skip(f"node {version.strip()} cannot load .ts files directly (needs >= 22.18)")
    result = subprocess.run([node, str(TS_PARITY)], capture_output=True, text=True, timeout=120, check=False, cwd=str(tmp_path))
    assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]
    assert re.search(r"^PASS \d+ cases$", result.stdout.strip().splitlines()[-1])
