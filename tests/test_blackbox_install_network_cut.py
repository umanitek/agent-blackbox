"""A network cut mid-install ends the installer's npm steps in bounded time, and the install then
fails and rolls back instead of hanging (KI-665, Linux round L1: with outbound 80/443 rejected at
"Setting up the OriginTrail DKG node", `npm install …dkg-10.0.26.tgz` waited 16 minutes with no
output, no timeout and no rollback).
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")


def _function(name: str) -> str:
    match = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", TEXT, re.MULTILINE | re.DOTALL)
    assert match is not None, name
    return match.group(0)


def test_a_step_that_hangs_is_stopped_and_says_so():
    script = _function("run_with_timeout") + 'run_with_timeout 1 sleep 60; echo "status=$?"'
    started = time.monotonic()
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30, check=False)
    assert time.monotonic() - started < 10, "bounded"
    assert "status=0" not in done.stdout and "blackbox: stopped after 1s: sleep" in done.stderr


def test_every_npm_network_step_of_the_dkg_install_is_bounded():
    for line in (line for line in TEXT.splitlines() if re.search(r"\bnpm (?:install --prefix|pack)\b", line) and not line.lstrip().startswith(("#", "echo", "warn"))):
        assert "run_with_timeout" in line and "BLACKBOX_NPM_STEP_SECONDS" in line, line
    assert re.search(r'^BLACKBOX_NPM_STEP_SECONDS="\$\{BLACKBOX_NPM_STEP_SECONDS:-\d+\}"', TEXT, re.MULTILINE)
    assert "--fetch-timeout=" in TEXT and "--fetch-retries=" in TEXT
