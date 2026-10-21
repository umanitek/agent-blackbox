"""Native command stderr and uv version checks under Windows PowerShell 5.1."""

import subprocess

import pytest

from tests.scripts.install.ps1_helpers import INSTALLER, _powershell

pytestmark = pytest.mark.platforms("windows")


def _dot_sourced(body: str) -> subprocess.CompletedProcess:
    script = f'$ErrorActionPreference = "Stop"; . "{INSTALLER}"; {body}'
    return subprocess.run([_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                          capture_output=True, text=True, timeout=120, check=False)


def test_native_stderr_under_stop_leaves_the_exit_code_to_the_caller():
    result = _dot_sourced('Invoke-Native { cmd /c "echo soft-failure 1>&2 & exit 3" 2>$null }; '
                          '"exit=$LASTEXITCODE preference=$ErrorActionPreference"')
    assert result.returncode == 0, result.stdout + result.stderr
    assert "exit=3 preference=Stop" in result.stdout


def test_path_uv_must_run_and_meet_the_pin(tmp_path):
    for name, body in {"old": "@echo uv 0.6.17", "new": "@echo uv 99.0.0 (abc 2099-01-01)",
                       "broken": "@echo boom 1>&2 & exit /b 1"}.items():
        (tmp_path / f"{name}.cmd").write_text(body + "\r\n")
    checks = "; ".join(f'"{n}=$(Test-UvAtLeastPin \'{tmp_path / (n + ".cmd")}\')"' for n in ("old", "new", "broken"))
    result = _dot_sourced(checks)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split() == ["old=False", "new=True", "broken=False"]
