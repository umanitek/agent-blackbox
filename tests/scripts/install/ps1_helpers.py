"""Native PowerShell and local Git fixtures for installer contract tests."""

import json
import os
from pathlib import Path
import shutil
import subprocess

INSTALLER = Path(__file__).resolve().parents[3] / "scripts" / "install.ps1"


def _powershell() -> str:
    powershell = shutil.which("powershell")
    assert powershell, "Windows PowerShell 5.1 is part of every supported Windows"
    return powershell


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _stage(origin: Path, home: Path, *extra: str, **env_extra: str) -> tuple[subprocess.CompletedProcess, dict]:
    env = dict(os.environ, HERMES_REPO_URL=str(origin), HERMES_HOME=str(home), **env_extra)
    result = subprocess.run([_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(INSTALLER),
                             "-Stage", "repository", "-Json", *extra],
                            env=env, capture_output=True, text=True, timeout=180, check=False)
    frames = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert len(frames) == 1, result.stdout + result.stderr
    return result, frames[0]


def _pin_fixture(tmp_path: Path) -> tuple[Path, str, str]:
    """main: pin <- tip; side: a commit off main."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "README").write_text("one", encoding="utf-8")
    _git(origin, "add", "README")
    _git(origin, "commit", "-qm", "one")
    pin = _git(origin, "rev-parse", "HEAD")
    (origin / "README").write_text("tip", encoding="utf-8")
    _git(origin, "commit", "-qam", "tip")
    _git(origin, "config", "uploadpack.allowFilter", "true")
    _git(origin, "checkout", "-qb", "side")
    (origin / "README").write_text("side", encoding="utf-8")
    _git(origin, "commit", "-qam", "side")
    off_branch = _git(origin, "rev-parse", "HEAD")
    _git(origin, "checkout", "-q", "main")
    return origin, pin, off_branch


def _clone_argv(trace: Path) -> list[str]:
    [line] = [line for line in trace.read_text(encoding="utf-8-sig", errors="replace").splitlines() if "built-in: git clone " in line]
    return line.split("built-in: git clone ", 1)[1].split()
