"""The Windows installer starts Blackbox at sign-in (parity with KI-022 / KI-296).

The Linux/macOS installer registers the DKG node and the dashboard as boot
services; the Windows installer registered nothing, so after a restart or
sign-out neither the node nor the dashboard (rule refresh + community pulse)
came back. Scheduled Tasks cannot run here, so: structural checks of the
registration, plus the launcher generator RUN in real PowerShell when pwsh is
installed (data handed over through the environment only — LES-037).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_PS1 = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.ps1"
PWSH = os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")


def _src() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


def _function(name: str) -> str:
    match = re.search(rf"^function {name} \{{.*?^\}}", _src(), re.DOTALL | re.MULTILINE)
    assert match is not None, f"{name} not found"
    return match.group(0)


def test_startup_tasks_are_registered_after_the_node_is_installed():
    main = _src().split("function Main {", 1)[1]
    assert main.index("Install-Dkg") < main.index("Register-BlackboxStartupTasks") < main.index("Show-NextSteps")


def test_tasks_are_per_user_at_sign_in_with_no_admin_rights():
    body = _function("Register-BlackboxStartupTasks")
    assert "-AtLogOn -User $env:USERNAME" in body
    assert "-LogonType Interactive -RunLevel Limited" in body
    assert '-TaskName $DkgTaskName' in body and '-TaskName "Agent Blackbox dashboard"' in body
    assert '$DkgTaskName = "Agent Blackbox DKG node"' in INSTALL_PS1.read_text(encoding="utf-8")
    assert '$trigger.Delay = "PT30S"' in body                      # the dashboard after the node
    assert "blackbox dashboard" in body


def test_missing_scheduled_tasks_or_node_only_warns():
    body = _function("Register-BlackboxStartupTasks")
    assert body.index("Get-Command Register-ScheduledTask") < body.index("Register-ScheduledTask -TaskName")
    assert "Test-Path $DkgBin" in body


@pytest.mark.skipif(PWSH is None, reason="PowerShell (pwsh) is not installed")
@pytest.mark.parametrize('backend', ['blazegraph', 'native'])
def test_the_node_launcher_carries_the_steady_state_settings(tmp_path, backend):
    """Run the real generator: same choices as the Linux unit — connection-time sync
    on (KI-044), stream + prefetch (KI-282), no reconciler override — and paths
    with an apostrophe stay one literal."""
    functions = tmp_path / "functions.ps1"
    functions.write_text(_function("ConvertTo-PsLiteral") + "\n" + _function("New-BlackboxDkgLauncherLines") + "\n",
                         encoding="utf-8")
    script = r"""
. $env:T_FUNCTIONS
$DkgHome = $env:T_DKG_HOME
$DkgBin = $env:T_DKG_BIN
$script:DkgDurableSyncEnabled = '1'
$DkgStoreQueueLimit = 512
$DkgListContextGraphsProjection = '1'
$DkgExactBatchStreamEnabled = '1'
$DkgVmRecoveryPrefetchEnabled = '1'
$script:DkgSelectedStoreBackend = $env:T_BACKEND
if ($env:T_BACKEND -eq 'native') { $DkgVmRecoveryPrefetchEnabled = '0' }
$script:DkgNodeOptions = '--max-old-space-size=8192'
New-BlackboxDkgLauncherLines -NodeDir $env:T_NODE_DIR
"""
    env = {**os.environ, "T_FUNCTIONS": str(functions), "T_DKG_HOME": r"C:\Users\O'Brien\agent-blackbox\.dkg",
           "T_DKG_BIN": r"C:\Users\O'Brien\agent-blackbox\dkg\node_modules\.bin\dkg.cmd", "T_NODE_DIR": r"C:\node", "T_BACKEND": backend}
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=120, env=env, check=False)

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert "$env:DKG_HOME = 'C:\\Users\\O''Brien\\agent-blackbox\\.dkg'" in lines
    expected = '0' if backend == 'native' else '1'
    assert f"$env:DKG_SYNC_ON_CONNECT_ENABLED = '{expected}'" in lines
    assert "$env:DKG_EXACT_BATCH_STREAM_ENABLED = '1'" in lines
    assert f"$env:DKG_VM_RECOVERY_PREFETCH_ENABLED = '{expected}'" in lines
    assert "$env:NODE_OPTIONS = '--max-old-space-size=8192'" in lines
    assert not any("DKG_SYNC_RECONCILER_ENABLED" in line for line in lines)
    assert lines[-1] == "& 'C:\\Users\\O''Brien\\agent-blackbox\\dkg\\node_modules\\.bin\\dkg.cmd' start --foreground"
