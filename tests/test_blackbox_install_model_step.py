"""The installer's last step: point a model-less agent at the dashboard's connect panel (2026-11-19).

Runs the real shell functions from scripts/blackbox-install.sh against a fake ``curl`` that plays
the dashboard's ``GET /api/agent-model``; detached from any terminal so nothing can prompt.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
PLUGIN_COPY = REPO_ROOT / "plugins" / "blackbox" / "setup" / "blackbox-install.sh"
FUNCTIONS = ("agent_model_state_from_dashboard", "open_in_browser", "offer_model_connect")


def _function(name: str) -> str:
    match = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", INSTALL_SH.read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def _run(tmp_path: Path, dashboard_body: str, incomplete: str = "false") -> str:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(f"#!/bin/sh\nprintf '%s' '{dashboard_body}'\n", encoding="utf-8")
    curl.chmod(0o755)
    for tool in ("cat", "sleep", "uname"):
        (bin_dir / tool).symlink_to(f"/bin/{tool}" if Path(f"/bin/{tool}").exists() else f"/usr/bin/{tool}")
    script = "\n".join([
        'heading() { printf "== %s\\n" "$1"; }', 'step() { printf -- "-> %s\\n" "$1"; }',
        "BLACKBOX_MODEL_STATE_WAIT_SECONDS=2", f"BLACKBOX_INSTALL_INCOMPLETE={incomplete}",
        *(_function(name) for name in FUNCTIONS), "offer_model_connect",
    ])
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": str(bin_dir), "HOME": str(tmp_path)}, start_new_session=True,
                          stdin=subprocess.DEVNULL, check=False)
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_a_model_less_agent_gets_the_connect_step(tmp_path):
    out = _run(tmp_path, '{"state":"missing","fix":"hermes setup --portal"}')
    assert "== One step left: connect your agent to an AI model" in out
    assert "http://127.0.0.1:9700/" in out
    assert "hermes setup --portal" in out


@pytest.mark.parametrize("body", ['{"state":"ready"}', '{"state":"unknown"}', ""])
def test_a_ready_or_unclear_agent_gets_nothing(tmp_path, body):
    assert "One step left" not in _run(tmp_path, body)   # an unclear answer says nothing (LES-011)


def test_an_incomplete_install_does_not_add_the_step(tmp_path):
    assert "One step left" not in _run(tmp_path, '{"state":"missing"}', incomplete="true")


def test_the_step_runs_last_and_both_installer_copies_match():
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "    next_steps\n    offer_model_connect\n}" in text
    assert PLUGIN_COPY.read_text(encoding="utf-8") == text
