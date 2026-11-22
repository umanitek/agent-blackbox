"""A restarted DKG node gets one named wait, long enough for a node that holds the whole graph.

KI-457 (bb-install-1022b, 2026-10-28): updating a synced install restarts its DKG node, which
then spends ~100 s reopening a store of ~10M triples; the installer waited a fixed 90 s, called
the node failed and rolled back a healthy machine. Every wait for a restarting node now reads
BLACKBOX_DKG_RUNTIME_WAIT_SECONDS (default 300): the installer's runtime wait and handover wait,
the Windows installer, and Blackbox's own restart in sync/managed_node.py.

KI-520/521 (E2E recheck 2026-11-21): a synced node needed ~6 min, past even 300 s. The wait now
follows the node's real progress — past the budget it keeps waiting only while the node is alive
under the same pid and its daemon.log advances, up to a ceiling; a crash loop or a stall fails at
once with its cause. The shell tests run the real functions out of the script against a fake
fingerprint helper and a fake node (daemon.pid / daemon.log).
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
from tests.plugins._blackbox_fakes import dkg_client_fake

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO / "scripts" / "blackbox-install.ps1"


def _body(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


_WAIT_SETTINGS = ("BLACKBOX_DKG_RUNTIME_WAIT_SECONDS=", "BLACKBOX_DKG_HANDOVER_WAIT_SECONDS=", "BLACKBOX_DKG_STALL_SECONDS=",
                  "BLACKBOX_DKG_LOAD_CEILING_SECONDS=", "BLACKBOX_DKG_WAIT_SLICE_SECONDS=")


def _settings(text: str) -> str:
    """The installer's own lines that set the waits (so the test runs what ships)."""
    lines = [line for line in text.splitlines() if line.startswith(_WAIT_SETTINGS)]
    assert len(lines) == len(_WAIT_SETTINGS), lines
    return "\n".join(lines)


def _run_wait(tmp_path: Path, *, env: dict[str, str] | None = None, ready_after: int = 0, progress: bool = True,
              alive: bool = True, restart_at: int = 0) -> tuple[list[str], str, str]:
    """Run wait_for_blackbox_dkg_runtime against a fake node. The fake fingerprint helper's
    ``wait`` answers ready on call *ready_after* (0: the first call; -1: never); each failing call
    takes 0.2 s and — with *progress* — adds a line to daemon.log. daemon.pid names a live process
    (*alive*); from call *restart_at* on it names another one (its service started it again).
    Returns (the slice each wait call was handed, the handover wait, the output)."""
    venv_bin, dkg = tmp_path / "venv" / "bin", tmp_path / "dkg"
    venv_bin.mkdir(parents=True); dkg.mkdir()
    record, count = tmp_path / "helper-args", tmp_path / "count"
    first = subprocess.Popen(["sleep", "120"]) if alive else None
    second = subprocess.Popen(["sleep", "120"]) if restart_at else None
    (dkg / "daemon.pid").write_text(f"{first.pid if first else 999999}\n", encoding="utf-8")
    helper = venv_bin / "python"
    helper.write_text(
        "#!/bin/sh\n"
        'shift\ncase "$1" in\n  commit) echo 71dfd4d74340aaaaaaaaaaaa ;;\n'
        f'  wait) echo "$4" >> {shlex.quote(str(record))}\n'
        f'    n=$(cat {shlex.quote(str(count))} 2>/dev/null || echo 0); echo $((n+1)) > {shlex.quote(str(count))}\n'
        f'    [ {ready_after} -ge 0 ] && [ "$n" -ge {ready_after} ] && exit 0\n'
        + (f'    [ "$n" -ge {restart_at} ] && echo {second.pid} > {shlex.quote(str(dkg / "daemon.pid"))}\n' if second else "")
        + (f'    echo "loading triples $n" >> {shlex.quote(str(dkg / "daemon.log"))}\n' if progress else "")
        + '    sleep 0.2; exit 1 ;;\nesac\n',
        encoding="utf-8")
    helper.chmod(0o755)
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = f"""
VENV_DIR={shlex.quote(str(tmp_path / "venv"))}
BLACKBOX_DKG_HOME={shlex.quote(str(dkg))}
BLACKBOX_DKG_CLI_DIR=/nonexistent
BLACKBOX_DKG_DAEMON_URL=http://127.0.0.1:9320
blackbox_helper() {{ echo helper.py; }}
explain_dkg_not_ready() {{ echo "EXPLAINED"; }}
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
step() {{ echo "STEP $*"; }}
{_settings(text)}
blackbox_dkg_live_pid() {{
{_body(text, "blackbox_dkg_live_pid")}
}}
blackbox_dkg_log_size() {{
{_body(text, "blackbox_dkg_log_size")}
}}
wait_for_blackbox_dkg_runtime() {{
{_body(text, "wait_for_blackbox_dkg_runtime")}
}}
wait_for_blackbox_dkg_runtime
echo "HANDOVER=$BLACKBOX_DKG_HANDOVER_WAIT_SECONDS"
"""
    run_env = {k: v for k, v in os.environ.items() if not k.startswith("BLACKBOX_DKG_")}
    run_env.update(env or {})
    try:
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, env=run_env, timeout=60)
    finally:
        for process in (first, second):
            if process:
                process.kill(); process.wait()
    handover = re.search(r"^HANDOVER=(\S+)$", result.stdout, re.MULTILINE)
    assert handover is not None, result.stdout + result.stderr
    handed = record.read_text(encoding="utf-8").split() if record.exists() else []
    return handed, handover[1], result.stdout


#: Short limits for the shell tests: wait 1 s, a node silent for 1 s is stuck, never past 30 s.
FAST = {"BLACKBOX_DKG_RUNTIME_WAIT_SECONDS": "1", "BLACKBOX_DKG_STALL_SECONDS": "1", "BLACKBOX_DKG_LOAD_CEILING_SECONDS": "30"}


def test_a_node_that_answers_at_once_is_ready_and_the_waits_default_to_five_minutes(tmp_path):
    handed, handover, output = _run_wait(tmp_path)
    assert "OK DKG daemon is ready" in output and handover == "300"
    assert handed == ["15"], "each call waits one slice; the five minutes are the installer's own budget"


def test_the_wait_is_a_setting_and_the_handover_wait_follows_it(tmp_path):
    _, handover, _ = _run_wait(tmp_path, env={"BLACKBOX_DKG_RUNTIME_WAIT_SECONDS": "600"})
    assert handover == "600"


def test_a_node_still_loading_past_the_budget_is_waited_for_while_it_makes_progress(tmp_path):
    """KI-520 (E2E recheck 2026-11-21): a synced node took ~6 min; the fixed 300 s wait rolled the update back."""
    _, _, output = _run_wait(tmp_path, env=FAST, ready_after=12)
    assert "OK DKG daemon is ready" in output
    assert "still loading its threat graph" in output and "keeps its last lists" in output


def test_a_node_that_stops_making_progress_fails_with_its_cause(tmp_path):
    _, _, output = _run_wait(tmp_path, env=FAST, ready_after=-1, progress=False)
    assert "has written nothing" in output and "EXPLAINED" in output and "OK DKG daemon is ready" not in output


def test_a_node_its_service_keeps_restarting_fails_at_once(tmp_path):
    """A crash loop (launchd starting the node again and again) is not "still loading": it fails
    before the five-minute budget, with its cause."""
    _, _, output = _run_wait(tmp_path, ready_after=-1, restart_at=2)
    assert "started it again" in output and "EXPLAINED" in output


def test_a_node_that_is_not_running_past_the_budget_fails(tmp_path):
    _, _, output = _run_wait(tmp_path, env=FAST, ready_after=-1, alive=False)
    assert "the node is not running" in output and "EXPLAINED" in output


def test_a_node_never_waits_past_the_ceiling(tmp_path):
    _, _, output = _run_wait(tmp_path, env={**FAST, "BLACKBOX_DKG_STALL_SECONDS": "60",
                                             "BLACKBOX_DKG_LOAD_CEILING_SECONDS": "2"}, ready_after=-1)
    assert "still starting after" in output and "OK DKG daemon is ready" not in output


def test_the_installer_has_no_fixed_runtime_wait_left():
    for path in (INSTALL_SH, INSTALL_PS1):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\$expected_?[cC]ommit\"? 90\b", text), path
    ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    assert "$env:BLACKBOX_DKG_RUNTIME_WAIT_SECONDS" in ps1 and "else { 300 }" in ps1


def test_the_windows_installer_follows_the_nodes_progress_like_the_mac_one():
    """KI-520/521 on Windows (recheck 2026-11-21): the .ps1 still made ONE fixed 300 s wait, so a
    synced install's update rolled back there too. No PowerShell runs in this suite's macOS lane
    (the parse test runs it on CI's Linux runner), so this pins the contract the shell harness
    above proves for the .sh: slice-by-slice waits, the same stall / ceiling / slice settings and
    defaults, a pid-change and not-running check, and no single fixed wait left."""
    ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    assert "$expectedCommit $DkgRuntimeWaitSeconds" not in ps1, "the one fixed wait is gone"
    assert "$expectedCommit $DkgWaitSliceSeconds" in ps1
    sh = INSTALL_SH.read_text(encoding="utf-8")
    for setting, variable, default in (("BLACKBOX_DKG_STALL_SECONDS", "$DkgStallSeconds", "180"),
                                       ("BLACKBOX_DKG_LOAD_CEILING_SECONDS", "$DkgLoadCeilingSeconds", "1800"),
                                       ("BLACKBOX_DKG_WAIT_SLICE_SECONDS", "$DkgWaitSliceSeconds", "15")):
        assert f'{setting}:-{default}' in sh, setting
        assert f"$env:{setting}" in ps1 and f"{variable} = " in ps1 and f"else {{ {default} }}" in ps1, setting
    for clue in ("the node is not running", "the node has written nothing for", "was started again",
                 "still loading its threat graph", "Get-BlackboxDkgLivePid", "Get-BlackboxDkgLogSize"):
        assert clue in ps1, clue


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
    monkeypatch.setattr(managed_node, "DkgClient", dkg_client_fake(lambda **_kw: _Node(clock, ready_after)))
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
