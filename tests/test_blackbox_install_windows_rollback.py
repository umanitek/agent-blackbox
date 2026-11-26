"""The Windows installer is all or nothing, like the macOS/Linux one (KI-436; KI-623; fix wave 7).

``blackbox-install.ps1`` had no rollback: a failed install left the checkout, ``.hermes``, the
DKG node and the PATH entry behind ("Windows does not roll a failed install back yet"). It now
records what is there before the first change (``Start-InstallRecord``) and, on any way out
before ``Complete-InstallRecord`` — an error, ``exit 1``, Ctrl+C — puts it back (``Undo-Install``,
run from the ``finally`` around ``Main``), saying only what it checked is gone.

These run the installer's OWN functions under PowerShell 7 (``pwsh``; GitHub's runners ship it,
``BLACKBOX_TEST_PWSH`` names another) in a throwaway folder. Skipped without PowerShell. What
needs a real Windows (the user PATH in the registry, Scheduled Tasks, Hermes's own Windows setup
through pm — KI-623) is the Windows VM's to prove.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_PS1 = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.ps1"
TEXT = INSTALL_PS1.read_text(encoding="utf-8")
PWSH = os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")
FUNCTIONS = ("Write-Step", "Write-Ok", "Write-Warn2", "Write-Err2", "Get-InstallCreatedPaths", "Get-InstallRewrittenPaths",
             "Test-InstallPathRemovable", "Start-InstallRecord", "Complete-InstallRecord", "Undo-Install",
             "Undo-InstallCheckout", "Get-InstallLeftovers", "Remove-UserPathEntry")
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main"]

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell (pwsh) is not installed")


def _function(name: str) -> str:
    one_line = re.search(rf"^function {re.escape(name)}\b[^\n]*\}}\n", TEXT, re.MULTILINE)
    found = one_line or re.search(rf"^function {re.escape(name)}\b.*?^\}}\n", TEXT, re.MULTILINE | re.DOTALL)
    assert found is not None, name
    return found.group(0)


def _run(home: Path, body: str) -> subprocess.CompletedProcess[str]:
    """*body* run with the record functions loaded; the installer's folders all under *home*."""
    script = "\n".join([
        '$ErrorActionPreference = "Stop"',
        f"$TestHome = '{home}'",
        "$DefaultRepoDir = Join-Path $TestHome 'agent-blackbox'",
        "$HermesHome = Join-Path $TestHome '.hermes'",
        "$BlackboxHome = Join-Path $HermesHome 'blackbox'",
        "$DkgHome = Join-Path $DefaultRepoDir '.dkg'",
        "$DkgCliDir = Join-Path $DefaultRepoDir 'dkg'",
        "$DkgBin = Join-Path $DkgCliDir 'node_modules/.bin/dkg'",
        "$DkgDaemonUrl = 'http://127.0.0.1:9'",   # nothing answers: no node was running
        "$BlackboxShimDir = Join-Path $TestHome '.local/bin'",
        "$StartupTaskNames = @('Agent Blackbox DKG node', 'Agent Blackbox dashboard')",
        "$script:InstallRecord = $null", "$script:InstallCommitted = $false", "$script:AddedUserPath = $null",
        "function Invoke-BlackboxDkgControl { }",
        *(_function(name) for name in FUNCTIONS),
        "try {", body, "} finally {",
        "    if ($script:InstallRecord -and -not $script:InstallCommitted) { Undo-Install }", "}",
    ])
    return _pwsh(home.parent / "under-test.ps1", script)


def _pwsh(file: Path, script: str) -> subprocess.CompletedProcess[str]:
    """*script* run as a file (``-File``: parsed whole, as the installer is)."""
    file.write_text(script, encoding="utf-8")
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(file)], capture_output=True, text=True,
                          timeout=120, check=False)


def _tree(root: Path) -> set[str]:
    return {str(path.relative_to(root)) for path in root.rglob("*") if ".git" not in path.relative_to(root).parts}


def test_a_failed_fresh_install_removes_everything_it_created(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "mine.txt").write_text("mine", encoding="utf-8")
    before = _tree(home)
    done = _run(home, """
Start-InstallRecord
New-Item -ItemType Directory -Force -Path (Join-Path $DefaultRepoDir 'dkg'), (Join-Path $BlackboxHome 'x'), $BlackboxShimDir | Out-Null
Set-Content -Path (Join-Path $HermesHome 'config.yaml') -Value 'plugins: [blackbox]'
Set-Content -Path (Join-Path $BlackboxShimDir 'blackbox.cmd') -Value '@echo off'
exit 1
""")
    assert done.returncode == 1, done.stderr
    assert "Nothing from this install attempt was left behind." in done.stdout
    assert _tree(home) == before
    assert not (home / ".local" / "bin" / "blackbox.cmd").exists()


def test_a_failed_upgrade_puts_back_what_it_rewrote_and_keeps_the_rest(tmp_path):
    home = tmp_path / "home"
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    (home / ".hermes" / "config.yaml").write_text("model: mine\n", encoding="utf-8")
    (home / ".hermes" / "blackbox" / "audit.jsonl").write_text("history\n", encoding="utf-8")
    done = _run(home, """
Start-InstallRecord
Set-Content -Path (Join-Path $HermesHome 'config.yaml') -Value 'model: broken'
New-Item -ItemType Directory -Force -Path (Join-Path $HermesHome 'plugins/blackbox') | Out-Null
throw 'the DKG node did not start'
""")
    assert done.returncode != 0
    assert "Nothing from this install attempt was left behind." in done.stdout, done.stdout + done.stderr
    assert (home / ".hermes" / "config.yaml").read_text(encoding="utf-8") == "model: mine\n"
    assert (home / ".hermes" / "blackbox" / "audit.jsonl").read_text(encoding="utf-8") == "history\n"
    assert not (home / ".hermes" / "plugins").exists()


def test_an_upgraded_checkout_goes_back_to_its_commit(tmp_path):
    home = tmp_path / "home"
    repo = home / "agent-blackbox"
    repo.mkdir(parents=True)
    subprocess.run([*GIT, "init", "-q"], cwd=repo, check=True)
    (repo / "pyproject.toml").write_text("# one\n", encoding="utf-8")
    subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True)
    subprocess.run([*GIT, "commit", "-q", "-m", "one"], cwd=repo, check=True)
    first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    done = _run(home, """
Start-InstallRecord
Set-Content -Path (Join-Path $DefaultRepoDir 'pyproject.toml') -Value '# two'
& git -C $DefaultRepoDir -c user.name=t -c user.email=t@example.invalid commit -q -am two
exit 1
""")
    assert done.returncode == 1, done.stderr
    now = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    assert now == first and "Nothing from this install attempt was left behind." in done.stdout


def test_a_committed_install_is_kept(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    done = _run(home, """
Start-InstallRecord
New-Item -ItemType Directory -Force -Path $BlackboxHome | Out-Null
Complete-InstallRecord
""")
    assert done.returncode == 0, done.stderr
    assert (home / ".hermes" / "blackbox").is_dir() and "Putting this machine back" not in done.stdout


def test_rollback_never_removes_the_home_folder_or_a_top_level_folder(tmp_path):
    done = _run(tmp_path, """
foreach ($path in @($HOME, '/', '/Users', 'relative/path', '')) { if (Test-InstallPathRemovable $path) { "REMOVABLE $path" } }
if (Test-InstallPathRemovable (Join-Path $TestHome 'agent-blackbox')) { 'CHECKOUT-REMOVABLE' }
""")
    assert done.returncode == 0, done.stderr
    assert "REMOVABLE" not in done.stdout.replace("CHECKOUT-REMOVABLE", "") and "CHECKOUT-REMOVABLE" in done.stdout


def test_hermes_own_windows_setup_is_used_when_the_checkout_has_it(tmp_path):
    """KI-623: with setup-hermes.ps1, pm\\lock.json and activate.ps1 in the checkout, the installer
    takes Hermes's own setup (pm), not a venv + pip; an older checkout keeps the venv."""
    repo = tmp_path / "repo"
    (repo / "pm").mkdir(parents=True)
    script = "\n".join([f"$RepoDir = '{repo}'", _function("Test-HermesOwnSetup"), "Test-HermesOwnSetup"])
    assert _pwsh(tmp_path / "probe.ps1", script).stdout.strip() == "False"
    for name in ("setup-hermes.ps1", "pm/lock.json", "activate.ps1"):
        (repo / name).write_text("{}", encoding="utf-8")
    assert _pwsh(tmp_path / "probe.ps1", script).stdout.strip() == "True"
