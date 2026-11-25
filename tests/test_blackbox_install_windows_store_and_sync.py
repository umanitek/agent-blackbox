"""The Windows installer matches the macOS/Linux one on the store and the first sync (KI-436 remainder).

``blackbox-install.sh`` (a) falls back to the DKG-managed Oxigraph store with yes as the default when
Docker cannot run Blazegraph (Enter or no answer within ``BLACKBOX_STORE_PROMPT_SECONDS`` takes it,
only an explicit "n" stops; no terminal: Oxigraph, saying why), (b) gives that store a free port
from 7879 (never the default 7878, which another DKG node on the machine very likely holds), written
into the node's ``store.options.port``, and (c) leaves the ~30-minute first threat-graph sync to the
dashboard, in the background. ``blackbox-install.ps1`` asked "[y/N]" (no answer: the install
stopped), wrote no port, and waited for ``blackbox sync --wait`` inside the install.

These run the installer's OWN functions under PowerShell 7 (``pwsh``; ``BLACKBOX_TEST_PWSH`` names
another), with the system's answers (a console, a port in use, Scheduled Tasks) stood in for by
small functions. Skipped without PowerShell. Nothing here starts a node, a dashboard or a task.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

INSTALL_PS1 = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.ps1"
TEXT = INSTALL_PS1.read_text(encoding="utf-8")
PWSH = os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")
OUTPUT = ("Write-Step", "Write-Ok", "Write-Warn2", "Write-Err2", "Write-Heading")

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell (pwsh) is not installed")


def _function(name: str) -> str:
    """The function's text; one holding a here-string (an embedded Python writer, whose own lines
    may start with "}") ends at the first closing brace after the here-string."""
    start = TEXT.index(f"\nfunction {name} ") + 1
    one_line = re.match(rf"function {re.escape(name)}\b[^\n]*\}}\n", TEXT[start:])
    if one_line:
        return one_line.group(0)
    closing = re.compile(r"^\}\n", re.MULTILINE)
    end = closing.search(TEXT, start)
    assert end is not None, name
    opening = TEXT.find("@'\n", start)
    if 0 <= opening < end.start():                 # the brace is inside the here-string: skip past it
        end = closing.search(TEXT, TEXT.index("\n'@", opening))
    return TEXT[start:end.end()]


def _setting(name: str) -> str:
    """The installer's own script-level line that sets ``$name``."""
    found = re.search(rf"^\${re.escape(name)} = [^\n]*$", TEXT, re.MULTILINE)
    assert found is not None, name
    return found.group(0)


def _pwsh(tmp_path: Path, lines: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """*lines* run as one file (parsed whole, as the installer is), with no console to read."""
    script = tmp_path / "under-test.ps1"
    script.write_text("\n".join(['$ErrorActionPreference = "Stop"', *(_function(name) for name in OUTPUT), *lines]),
                      encoding="utf-8")
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=120, env={**os.environ, **(env or {})}, check=False)


# (a) The Oxigraph fallback: yes by default.

def _confirm(tmp_path: Path, answer: str | None) -> subprocess.CompletedProcess[str]:
    """``Confirm-OxigraphFallback`` with a person at the console typing *answer* ("" = Enter or no
    answer in time), or with no console at all (None)."""
    stand_ins = ["function Test-InteractiveConsole { return $false }"] if answer is None else [
        "function Test-InteractiveConsole { return $true }",
        f"function Read-AnswerWithin([int]$Seconds) {{ Write-Host \"asked for $Seconds s\"; return '{answer}' }}"]
    return _pwsh(tmp_path, [_setting("StorePromptSeconds"), *stand_ins, _function("Confirm-OxigraphFallback"),
                            'if (Confirm-OxigraphFallback "Docker is unavailable.") { "CHOSE=oxigraph" } else { "CHOSE=stop" }'],
                 env={"BLACKBOX_STORE_PROMPT_SECONDS": "7"})


@pytest.mark.parametrize("answer", ["", "y", "yes", "maybe"])
def test_enter_no_answer_in_time_or_anything_but_n_takes_oxigraph(tmp_path, answer):
    done = _confirm(tmp_path, answer)
    assert done.returncode == 0, done.stderr
    assert "CHOSE=oxigraph" in done.stdout
    assert "Continue with Oxigraph? [Y/n] (yes in 7s)" in done.stdout and "asked for 7 s" in done.stdout


@pytest.mark.parametrize("answer", ["n", "N", "no", " NO "])
def test_only_an_explicit_n_stops_the_install(tmp_path, answer):
    done = _confirm(tmp_path, answer)
    assert done.returncode == 0, done.stderr
    assert "CHOSE=stop" in done.stdout and "Stopping without installing" in done.stdout


def test_with_no_terminal_oxigraph_is_chosen_and_the_run_says_why(tmp_path):
    done = _confirm(tmp_path, None)
    assert done.returncode == 0, done.stderr
    assert "CHOSE=oxigraph" in done.stdout and "No terminal to ask" in done.stdout


def test_a_non_interactive_powershell_is_no_terminal_to_ask(tmp_path):
    """The real check: ``-NonInteractive`` with no console input is never asked (an agent, a script)."""
    done = _pwsh(tmp_path, [_function("Test-InteractiveConsole"), '"INTERACTIVE=$(Test-InteractiveConsole)"'])
    assert done.returncode == 0, done.stderr
    assert "INTERACTIVE=False" in done.stdout


# (b) A free Oxigraph port from 7879, written into the node's config.

def _port(tmp_path: Path, busy: list[int], already_running: bool = False) -> str:
    done = _pwsh(tmp_path, [
        f"$script:Busy = @({', '.join(map(str, busy)) or ''})",
        "function Test-PortInUse { param([int]$Port) return $script:Busy -contains $Port }",
        f"$script:DkgAlreadyRunning = ${str(already_running).lower()}",
        _setting("OxigraphFirstPort"), _setting("OxigraphLastPort"), _function("Select-BlackboxOxigraphPort"),
        "$port = Select-BlackboxOxigraphPort", 'if ($null -eq $port) { "PORT=none" } else { "PORT=[$port]" }'])
    assert done.returncode == 0, done.stderr
    return re.search(r"PORT=(\S+)", done.stdout).group(1)


def test_the_store_gets_the_first_free_port_above_the_default(tmp_path):
    assert _port(tmp_path, []) == "[7879]"                       # 7878 is never taken, even when free
    assert _port(tmp_path, [7878, 7879, 7880]) == "[7881]"


def test_a_running_blackbox_node_keeps_its_port_and_a_full_range_is_refused(tmp_path):
    assert _port(tmp_path, [], already_running=True) == "[]"     # the config is left as it is
    assert _port(tmp_path, list(range(7879, 7979))) == "none"


def _write_config(tmp_path: Path, dkg_home: Path, busy: list[int], store_url: str = "") -> subprocess.CompletedProcess[str]:
    """The installer's real ``Ensure-BlackboxDkgConfig`` (its Python writer run by this Python) for
    a DKG-managed Oxigraph store."""
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    return _pwsh(tmp_path, [
        f"$env:TEMP = '{temp}'", f"$VenvPython = '{sys.executable}'", f"$DkgHome = '{dkg_home}'", "$DkgPort = 9320",
        '$script:DkgSelectedStoreBackend = "oxigraph-server"', f"$DkgStoreUrl = '{store_url}'", "$DkgStoreManagedByDkg = $false",
        '$ContextGraphId = "graph"', '$DefaultContextGraphId = "graph"', '$DkgSyncGlobalMaxInflight = "4"',
        '$DkgSyncGlobalQueueLimit = "8"', "$script:DkgAlreadyRunning = $false",
        f"$script:Busy = @({', '.join(map(str, busy))})",
        "function Test-PortInUse { param([int]$Port) return $script:Busy -contains $Port }",
        _setting("OxigraphFirstPort"), _setting("OxigraphLastPort"), _function("Select-BlackboxOxigraphPort"),
        _function("Ensure-BlackboxDkgConfig"), "Ensure-BlackboxDkgConfig"])


def test_a_fresh_node_config_names_the_chosen_port_and_the_other_settings_stay_in_place(tmp_path):
    dkg_home = tmp_path / "dkg"
    done = _write_config(tmp_path, dkg_home, busy=[7879])
    assert done.returncode == 0, done.stdout + done.stderr
    config = json.loads((dkg_home / "config.json").read_text(encoding="utf-8"))
    assert config["store"] == {"backend": "oxigraph-server", "options": {"port": 7880}}
    # Every argument after the empty store URL reached its own place (Windows PowerShell 5.1
    # drops an empty argument to a native program, which would shift them).
    assert config["syncGlobalMaxInflight"] == 4 and config["syncGlobalQueueLimit"] == 8
    assert config["syncReconcilerEnabled"] is False             # the default graph's native profile


def test_a_port_the_config_already_names_is_kept(tmp_path):
    dkg_home = tmp_path / "dkg"
    dkg_home.mkdir()
    (dkg_home / "config.json").write_text(json.dumps({"store": {"backend": "oxigraph-server", "options": {"port": 7900}}}),
                                          encoding="utf-8")
    done = _write_config(tmp_path, dkg_home, busy=[])
    assert done.returncode == 0, done.stdout + done.stderr
    assert json.loads((dkg_home / "config.json").read_text(encoding="utf-8"))["store"]["options"] == {"port": 7900}


# (c) The first threat-graph sync runs in the background.

def _sync_step(tmp_path: Path, auto_dashboard: str, task_registered: bool,
               hermes: str = "Fake-Hermes") -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """``Sync-Ruleset`` then ``Start-BlackboxDashboard`` with a Hermes (a function, or the file
    *hermes*), Scheduled Tasks and processes that only record."""
    calls = tmp_path / "calls.txt"
    done = _pwsh(tmp_path, [
        f"$Calls = '{calls}'",
        "function Fake-Hermes { Add-Content -LiteralPath $Calls -Value (\"hermes \" + ($args -join ' ')) }",
        "function Start-ScheduledTask { param([string]$TaskName, $ErrorAction) Add-Content -LiteralPath $Calls -Value \"task $TaskName\" }",
        "function Start-Process { param($FilePath, $ArgumentList, $WindowStyle) Add-Content -LiteralPath $Calls -Value \"process $FilePath $ArgumentList\" }",
        f"$script:HermesBin = '{hermes}'", "$script:DkgReady = $true",
        f"$script:DashboardTaskRegistered = ${str(task_registered).lower()}", '$HermesHome = "h"',
        _setting("AutoDashboard"), _setting("DashboardOffPattern"), _setting("DashboardTaskName"), _setting("DashboardUrl"),
        _function("Sync-Ruleset"), _function("Start-BlackboxDashboard"), "Sync-Ruleset", "Start-BlackboxDashboard"],
        env={"BLACKBOX_AUTO_DASHBOARD": auto_dashboard})
    return done, calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def test_the_install_does_not_wait_for_the_first_sync_and_says_it_runs_in_the_background(tmp_path):
    done, calls = _sync_step(tmp_path, "1", task_registered=True)
    assert done.returncode == 0, done.stderr
    assert not [call for call in calls if call.startswith("hermes")]        # no `blackbox sync --wait` inside the install
    assert "runs in the background (about 30 minutes)" in done.stdout
    assert calls == ["task Agent Blackbox dashboard"]                     # the dashboard (and its sync worker) starts now


def test_without_the_sign_in_task_the_dashboard_starts_as_its_own_process(tmp_path):
    hermes = tmp_path / "hermes.exe"
    hermes.write_text("", encoding="utf-8")
    done, calls = _sync_step(tmp_path, "1", task_registered=False, hermes=str(hermes))
    assert done.returncode == 0, done.stderr
    assert calls == [f"process {hermes} blackbox dashboard"]


def test_with_the_dashboard_off_nothing_starts_and_the_sync_command_is_named(tmp_path):
    done, calls = _sync_step(tmp_path, "0", task_registered=True)
    assert done.returncode == 0, done.stderr
    assert calls == []
    assert "blackbox sync --wait --require-rules" in done.stdout and "auto-start disabled" in done.stdout
