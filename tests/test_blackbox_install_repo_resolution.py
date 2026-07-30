"""Regression coverage for Agent Blackbox installer checkout resolution."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO_ROOT / "scripts" / "blackbox-install.ps1"


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"{name}\(\) \{{.*?\n\}}", text, re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def test_shell_installer_defaults_to_invocation_directory() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    assert 'BLACKBOX_INSTALL_ROOT="$PWD/agent-blackbox"' in text
    assert 'BLACKBOX_INSTALL_ROOT="$HOME/agent-blackbox"' not in text


def test_shell_installer_rejects_incomplete_existing_checkout() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    validity = re.search(
        r"blackbox_repo_is_valid\(\) \{.*?\n\}", text, re.DOTALL
    )

    assert validity is not None
    block = validity.group(0)
    assert "rev-parse --verify HEAD" in block
    assert 'pyproject.toml' in block
    assert 'plugins/blackbox' in block
    assert "move_broken_blackbox_repo_aside" in text
    assert '|| true' not in re.search(
        r"resolve_repo\(\) \{.*?\n\}", text, re.DOTALL
    ).group(0)


def test_powershell_installer_matches_checkout_contract() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'Join-Path ([string](Get-Location)) "agent-blackbox"' in text
    assert '$env:USERPROFILE\\agent-blackbox' not in text
    assert "function Test-BlackboxRepoCheckout" in text
    assert "rev-parse --verify HEAD" in text
    assert 'Test-Path "$Path\\pyproject.toml"' in text
    assert 'Test-Path "$Path\\plugins\\blackbox"' in text
    assert "Move-BrokenBlackboxRepoAside" in text
    assert "Move-Item -LiteralPath $Path" in text


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
def test_shell_installer_replaces_incomplete_checkout_with_real_clone(
    tmp_path: Path,
) -> None:
    """Exercise the reported state: Git exists, project markers do not."""
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True)
    (source / "pyproject.toml").write_text("[project]\nname='agent-blackbox'\n")
    (source / "plugins" / "blackbox").mkdir(parents=True)
    (source / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "fixture",
        ],
        cwd=source,
        check=True,
        capture_output=True,
    )

    install_dir = tmp_path / "agent-blackbox"
    install_dir.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=install_dir, check=True)
    (install_dir / "partial.txt").write_text("interrupted checkout\n")
    subprocess.run(["git", "add", "."], cwd=install_dir, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "partial",
        ],
        cwd=install_dir,
        check=True,
        capture_output=True,
    )

    text = INSTALL_SH.read_text(encoding="utf-8")
    functions = "\n".join(
        _shell_function(text, name)
        for name in (
            "blackbox_repo_is_valid",
            "move_broken_blackbox_repo_aside",
            "resolve_repo",
        )
    )
    script = f"""
set -euo pipefail
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ printf '%s\\n' "$*" >&2; }}
BLACKBOX_INSTALL_ROOT={shlex.quote(str(install_dir))}
REPO_URL={shlex.quote(str(source))}
REPO_BRANCH=main
{functions}
resolve_repo
"""
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert (install_dir / "pyproject.toml").is_file()
    assert (install_dir / "plugins" / "blackbox").is_dir()
    backups = list(tmp_path.glob("agent-blackbox.broken-*"))
    assert len(backups) == 1
    assert (backups[0] / "partial.txt").read_text() == "interrupted checkout\n"
