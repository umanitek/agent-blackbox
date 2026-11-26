"""The Windows installer (``scripts/blackbox-install.ps1``) run the documented way, ``iwr -useb … |
iex``, and from a checkout — driven through PowerShell 7 (``pwsh``) on any machine.

KI-655 (security round 7, Windows 11 ARM64, PowerShell 5.1, High): the one-liner threw at once,
"Cannot bind argument to parameter 'Path' because it is an empty string": under ``iex`` there is no
script path, ``$PSCommandPath`` is empty, and ``Test-RunsFromBlackboxCheckout`` / ``Resolve-Repo``
ran ``Split-Path -Parent $PSCommandPath`` under ``$ErrorActionPreference = "Stop"``. The script's
own path is now read in ONE place (``$InstallerCheckoutDir``). These tests run the script's TEXT
through ``Invoke-Expression`` (what ``iex`` does), every definition and top-level line of it, then
call the functions ``Main`` calls first.

KI-656 / KI-657 (same round, Medium/High): the install waited FOREVER on Windows administrator
prompts nobody could answer — winget's machine-wide Node MSI, and Visual Studio Build Tools that
Hermes's setup installs on ARM64. Node now comes per user from nodejs.org's zip (pinned sha256,
no prompt); a missing ARM64 toolchain stops the install BEFORE Hermes's setup with the one command
to run as administrator; and any prompt the install still causes is said and timed out
(``Wait-WithElevationWatch``). The Windows-only calls are stood in for by PowerShell functions of
the same name (a function wins over a cmdlet), so the logic runs on any machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_PS1 = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.ps1"
PWSH = os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")
#: Where the script stops defining and starts running: everything before it is definitions and settings.
RUN_MARKER = "# Any way out before Complete-InstallRecord"

pytestmark = pytest.mark.skipif(not PWSH, reason="PowerShell (pwsh) is not installed")


def _definitions() -> str:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    assert RUN_MARKER in text
    return text.split(RUN_MARKER, 1)[0]


def _pwsh(command: str, cwd: Path, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "USERPROFILE": str(cwd), "LOCALAPPDATA": str(cwd / "AppData" / "Local"), **(env_extra or {})}
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True,
                          timeout=180, cwd=cwd, env=env, check=False)


def test_the_script_text_run_through_invoke_expression_does_not_throw_on_its_own_path(tmp_path):
    """The one-liner's way in: no script path at all."""
    (tmp_path / "definitions.ps1").write_text(_definitions(), encoding="utf-8")
    command = ("$ErrorActionPreference = 'Stop'; "
               f"Get-Content -Raw -LiteralPath '{tmp_path / 'definitions.ps1'}' | Invoke-Expression; "
               "'checkout=' + [string]$InstallerCheckoutDir; 'runs-from-checkout=' + (Test-RunsFromBlackboxCheckout)")
    done = _pwsh(command, tmp_path)
    assert done.returncode == 0, done.stderr[-3000:]
    assert "Cannot bind argument" not in done.stderr
    assert "checkout=\n" in done.stdout + "\n" and "runs-from-checkout=False" in done.stdout


def test_run_from_a_checkout_the_script_still_finds_it(tmp_path):
    """The other way in (``.\\scripts\\blackbox-install.ps1`` in a clone) keeps using that clone."""
    repo = tmp_path / "agent-blackbox"
    (repo / "scripts").mkdir(parents=True)
    (repo / "plugins" / "blackbox").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    script = repo / "scripts" / "blackbox-install.ps1"
    script.write_text(_definitions(), encoding="utf-8")
    done = _pwsh(f". '{script}'; 'checkout=' + $InstallerCheckoutDir; 'runs-from-checkout=' + (Test-RunsFromBlackboxCheckout)",
                 tmp_path)
    assert done.returncode == 0, done.stderr[-3000:]
    assert f"checkout={repo}" in done.stdout and "runs-from-checkout=True" in done.stdout


def _run_defined(tmp_path: Path, body: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """*body* run after the installer's definitions were loaded through Invoke-Expression."""
    (tmp_path / "definitions.ps1").write_text(_definitions(), encoding="utf-8")
    command = (f"Get-Content -Raw -LiteralPath '{tmp_path / 'definitions.ps1'}' | Invoke-Expression; "
               "$ErrorActionPreference = 'Stop'; " + body)
    return _pwsh(command, tmp_path, env_extra)


def test_a_missing_node_is_installed_per_user_never_through_winget(tmp_path):
    """No winget (its Node is a machine-wide MSI: a UAC prompt); the zip is refused when its
    sha256 is not the pinned one, and the person is told the per-user way."""
    body = ("function winget { 'WINGET-CALLED' }; function Test-NodeOk { $false }; "
            "function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing) Write-Host ('URL=' + $Uri); "
            "  Set-Content -LiteralPath $OutFile -Value 'not node' }; "
            "$SkipDkg = $false; Test-NodeJs; 'has-node=' + $script:HasNode")
    done = _run_defined(tmp_path, body, {"PROCESSOR_ARCHITECTURE": "ARM64"})
    out = done.stdout + done.stderr
    assert done.returncode == 0, out[-3000:]
    assert "WINGET-CALLED" not in out
    assert "URL=https://nodejs.org/dist/v" in out and "-win-arm64.zip" in out
    assert "did not match its pinned checksum" in out and "has-node=False" in out
    assert "for this user" in out and "no administrator" in out


def test_an_unanswered_administrator_prompt_is_said_and_timed_out(tmp_path):
    """A step that raised a UAC prompt (consent.exe running) is stopped after the timeout, with
    the command to run as administrator — never an endless wait."""
    body = ("function Get-Process { param($Name, $Id, $ErrorAction) if ($Name -eq 'consent') { [pscustomobject]@{ Name = 'consent' } } }; "
            "$ElevationTimeoutSeconds = 2; $ElevationPollSeconds = 1; "
            "$p = Start-Process -FilePath ([Environment]::ProcessPath) -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep 120') -PassThru; "
            "$started = Get-Date; $ok = Wait-WithElevationWatch $p 'Node.js' 'ADMIN-COMMAND'; "
            "'ok=' + $ok; 'seconds=' + [int]((Get-Date) - $started).TotalSeconds; 'exited=' + $p.HasExited")
    done = _run_defined(tmp_path, body)
    out = done.stdout + done.stderr
    assert done.returncode == 0, out[-3000:]
    assert "ok=False" in out and "exited=True" in out
    assert int(out.split("seconds=", 1)[1].split()[0]) < 30
    assert "Windows is asking for administrator permission for Node.js" in out
    assert "Administrator PowerShell" in out and "ADMIN-COMMAND" in out


def test_a_step_without_a_prompt_is_waited_for_to_its_end(tmp_path):
    body = ("$ElevationPollSeconds = 1; "
            "$p = Start-Process -FilePath ([Environment]::ProcessPath) -ArgumentList @('-NoProfile', '-Command', 'exit 3') -PassThru; "
            "$null = $p.Handle; 'ok=' + (Wait-WithElevationWatch $p 'x' 'y'); 'code=' + $p.ExitCode")
    done = _run_defined(tmp_path, body)
    assert "ok=True" in done.stdout and "code=3" in done.stdout, done.stdout + done.stderr


def _repo_with_discovery(tmp_path: Path, visual_studio: str) -> Path:
    """A checkout whose Hermes discovery (scripts/windows-build-deps.ps1) answers *visual_studio*."""
    repo = tmp_path / "agent-blackbox"
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts" / "windows-build-deps.ps1").write_text(
        f"function Get-HermesArm64VisualStudio {{ {visual_studio} }}\n"
        "function Get-HermesClang { param([string]$VisualStudio) if ($VisualStudio) { 'clang.exe' } }\n", encoding="utf-8")
    return repo


def test_arm64_without_build_tools_stops_before_hermes_setup_with_the_admin_command(tmp_path):
    repo = _repo_with_discovery(tmp_path, "$null")
    body = f"function Test-IsAdministrator {{ $false }}; 'ready=' + (Test-WindowsBuildToolsReady '{repo}')"
    done = _run_defined(tmp_path, body, {"PROCESSOR_ARCHITECTURE": "ARM64", "BLACKBOX_ALLOW_ADMIN_PROMPT": ""})
    out = done.stdout + done.stderr
    assert "ready=False" in out, out[-3000:]
    assert "Administrator PowerShell" in out and "Microsoft.VisualStudio.Component.VC.Tools.ARM64" in out


@pytest.mark.parametrize("visual_studio, arch, admin, allow", [
    ("'C:\\VS'", "ARM64", "$false", ""),      # the tools are there
    ("$null", "AMD64", "$false", ""),           # x64 builds from wheels
    ("$null", "ARM64", "$true", ""),            # elevated: no prompt to wait on
    ("$null", "ARM64", "$false", "1"),          # the person chose to answer the prompt
])
def test_build_tools_check_lets_the_install_go_on_when_no_prompt_is_waited_on(tmp_path, visual_studio, arch, admin, allow):
    repo = _repo_with_discovery(tmp_path, visual_studio)
    body = f"function Test-IsAdministrator {{ {admin} }}; 'ready=' + (Test-WindowsBuildToolsReady '{repo}')"
    done = _run_defined(tmp_path, body, {"PROCESSOR_ARCHITECTURE": arch, "BLACKBOX_ALLOW_ADMIN_PROMPT": allow})
    assert "ready=True" in done.stdout, done.stdout + done.stderr
