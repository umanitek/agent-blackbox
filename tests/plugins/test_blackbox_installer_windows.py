"""The Windows installer (``scripts/blackbox-install.ps1``) run the documented way, ``iwr -useb … |
iex``, and from a checkout — driven through PowerShell 7 (``pwsh``) on any machine.

KI-655 (security round 7, Windows 11 ARM64, PowerShell 5.1, High): the one-liner threw at once,
"Cannot bind argument to parameter 'Path' because it is an empty string": under ``iex`` there is no
script path, ``$PSCommandPath`` is empty, and ``Test-RunsFromBlackboxCheckout`` / ``Resolve-Repo``
ran ``Split-Path -Parent $PSCommandPath`` under ``$ErrorActionPreference = "Stop"``. The script's
own path is now read in ONE place (``$InstallerCheckoutDir``). These tests run the script's TEXT
through ``Invoke-Expression`` (what ``iex`` does), every definition and top-level line of it, then
call the functions ``Main`` calls first.
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
