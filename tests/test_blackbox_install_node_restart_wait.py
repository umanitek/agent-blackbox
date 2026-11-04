"""A restarted DKG node gets one named wait, long enough for a node that holds the whole graph.

KI-457 (bb-install-1022b, 2026-10-28): updating a synced install restarts its DKG node, which
then spends ~100 s reopening a store of ~10M triples; the installer waited a fixed 90 s, called
the node failed and rolled back a healthy machine. Every wait for a restarting node now reads
BLACKBOX_DKG_RUNTIME_WAIT_SECONDS (default 300): the installer's runtime wait and handover wait,
the Windows installer, and Blackbox's own restart in sync/managed_node.py.

The shell tests run the real `wait_for_blackbox_dkg_runtime` out of the script against a fake
fingerprint helper that records the timeout it was handed.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.kernel.dkg_client import DkgError
from plugins.blackbox.sync import managed_node

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO / "scripts" / "blackbox-install.ps1"


def _body(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _settings(text: str) -> str:
    """The installer's own lines that set the two waits (so the test runs what ships)."""
    lines = [line for line in text.splitlines()
             if line.startswith(("BLACKBOX_DKG_RUNTIME_WAIT_SECONDS=", "BLACKBOX_DKG_HANDOVER_WAIT_SECONDS="))]
    assert len(lines) == 2, lines
    return "\n".join(lines)


def _run_wait(tmp_path: Path, *, env_wait: str | None = None, answers: bool = True) -> tuple[str, str, str]:
    """Run wait_for_blackbox_dkg_runtime; return (timeout the helper got, handover wait, output)."""
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    record = tmp_path / "helper-args"
    helper = venv_bin / "python"
    helper.write_text(
        "#!/bin/sh\n"
        f'shift\ncase "$1" in\n  commit) echo 71dfd4d74340aaaaaaaaaaaa ;;\n'
        f'  wait) echo "$4" > {shlex.quote(str(record))}; {"exit 0" if answers else "exit 1"} ;;\nesac\n',
        encoding="utf-8")
    helper.chmod(0o755)
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = f"""
VENV_DIR={shlex.quote(str(tmp_path / "venv"))}
BLACKBOX_DKG_CLI_DIR=/nonexistent
BLACKBOX_DKG_DAEMON_URL=http://127.0.0.1:9320
blackbox_helper() {{ echo helper.py; }}
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
step() {{ echo "STEP $*"; }}
{_settings(text)}
wait_for_blackbox_dkg_runtime() {{
{_body(text, "wait_for_blackbox_dkg_runtime")}
}}
wait_for_blackbox_dkg_runtime
echo "HANDOVER=$BLACKBOX_DKG_HANDOVER_WAIT_SECONDS"
"""
    env = {k: v for k, v in os.environ.items() if not k.startswith("BLACKBOX_DKG_")}
    if env_wait is not None:
        env["BLACKBOX_DKG_RUNTIME_WAIT_SECONDS"] = env_wait
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, env=env)
    handover = re.search(r"^HANDOVER=(\S+)$", result.stdout, re.MULTILINE)
    assert handover is not None, result.stdout + result.stderr
    return record.read_text(encoding="utf-8").strip(), handover[1], result.stdout


def test_the_installer_waits_five_minutes_for_a_restarted_node_by_default(tmp_path):
    timeout, handover, output = _run_wait(tmp_path)
    assert timeout == "300" and handover == "300"
    assert "OK DKG daemon is ready" in output and "up to 300s" in output


def test_the_wait_is_a_setting_and_the_handover_wait_follows_it(tmp_path):
    timeout, handover, _ = _run_wait(tmp_path, env_wait="600")
    assert timeout == "600" and handover == "600"


def test_a_node_that_never_answers_still_fails_and_says_how_to_wait_longer(tmp_path):
    _, _, output = _run_wait(tmp_path, answers=False)
    assert "within 300s" in output and "BLACKBOX_DKG_RUNTIME_WAIT_SECONDS=600" in output
    assert "OK DKG daemon is ready" not in output


def test_the_installer_has_no_fixed_runtime_wait_left():
    for path in (INSTALL_SH, INSTALL_PS1):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\$expected_?[cC]ommit\"? 90\b", text), path
    ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    assert "$env:BLACKBOX_DKG_RUNTIME_WAIT_SECONDS" in ps1 and "else { 300 }" in ps1
    assert "$expectedCommit $DkgRuntimeWaitSeconds" in ps1


def test_the_plugin_ships_the_same_installers():
    for name in ("blackbox-install.sh", "blackbox-install.ps1"):
        shipped = (REPO / "plugins" / "blackbox" / "setup" / name).read_bytes()
        assert shipped == (REPO / "scripts" / name).read_bytes(), name


# ---------------------------------------------------------------- Blackbox's own restart


@pytest.mark.parametrize("value,expected", [(None, 300.0), ("600", 600.0), ("0", 300.0), ("-5", 300.0),
                                            ("soon", 300.0), ("  ", 300.0), ("45.5", 45.5)])
def test_the_wait_setting_never_falls_below_a_positive_number(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv(managed_node.NODE_READY_WAIT_ENV, raising=False)
    else:
        monkeypatch.setenv(managed_node.NODE_READY_WAIT_ENV, value)
    assert managed_node.node_ready_wait_seconds() == expected


class _Clock:
    """A fake clock: sleep() moves time on, so a 300 s wait runs instantly."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _Node:
    """A node API that starts answering after *ready_after* seconds of the fake clock."""

    def __init__(self, clock: _Clock, ready_after: float) -> None:
        self.clock, self.ready_at = clock, clock.now + ready_after

    def status(self, timeout: float = 0) -> dict[str, str]:
        if self.clock.now < self.ready_at:
            raise DkgError("connection refused")
        return {"ok": "true"}


def _patched(monkeypatch, ready_after: float) -> None:
    clock = _Clock()
    monkeypatch.setattr(managed_node, "time", clock)
    monkeypatch.setattr(managed_node, "DkgClient", lambda **_kw: _Node(clock, ready_after))
    monkeypatch.delenv(managed_node.NODE_READY_WAIT_ENV, raising=False)


def test_a_synced_node_that_needs_100_seconds_is_waited_for(monkeypatch, tmp_path):
    _patched(monkeypatch, ready_after=100)
    managed_node._wait_for_managed_dkg_ready(_cfg(tmp_path), "")   # returns: ready inside 300 s


def test_a_node_that_never_answers_raises_naming_the_wait_and_the_setting(monkeypatch, tmp_path):
    _patched(monkeypatch, ready_after=10_000)
    with pytest.raises(RuntimeError, match=r"within 300s \(set BLACKBOX_DKG_RUNTIME_WAIT_SECONDS"):
        managed_node._wait_for_managed_dkg_ready(_cfg(tmp_path), "")


def _cfg(tmp_path: Path):
    from plugins.blackbox.kernel.config import BlackboxConfig
    return BlackboxConfig(dkg_home=str(tmp_path))
