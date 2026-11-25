"""Regression coverage for Agent Blackbox installer checkout resolution."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.plugins._blackbox_installer_shell import functions_with_callees


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO_ROOT / "scripts" / "blackbox-install.ps1"
#: The output helpers each test program defines itself (quiet, or errors to stderr).
STUBBED = ("step", "ok", "warn", "err")


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


# These run the installer's update path against throwaway git repos they
# create under tmp_path (never the real checkout); the live-system guard
# blocks any command mentioning a hermes update, so they carry its bypass mark.
_THROWAWAY_REPO_UPDATE = pytest.mark.live_system_guard_bypass


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
@_THROWAWAY_REPO_UPDATE
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
    functions = functions_with_callees(text, ["resolve_repo"], provided=STUBBED)
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
        ["bash", "-c", script], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    assert (install_dir / "pyproject.toml").is_file()
    assert (install_dir / "plugins" / "blackbox").is_dir()
    backups = list(tmp_path.glob("agent-blackbox.broken-*"))
    assert len(backups) == 1
    assert (backups[0] / "partial.txt").read_text() == "interrupted checkout\n"


def _commit_all(repo: Path, message: str) -> None:
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-m", message], cwd=repo, check=True, capture_output=True)


def _resolve_repo(install_dir: Path, source: Path, branch: str) -> subprocess.CompletedProcess:
    text = INSTALL_SH.read_text(encoding="utf-8")
    functions = functions_with_callees(text, ["resolve_repo"], provided=STUBBED)
    script = f"""
set -euo pipefail
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ printf '%s\\n' "$*" >&2; }}
BLACKBOX_INSTALL_ROOT={shlex.quote(str(install_dir))}
REPO_URL={shlex.quote(source.as_uri())}
REPO_BRANCH={shlex.quote(branch)}
{functions}
resolve_repo
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
@_THROWAWAY_REPO_UPDATE
def test_shell_installer_moves_an_existing_install_to_another_branch(tmp_path: Path) -> None:
    """KI-287: the installer clones one branch, shallow. Re-running it with
    BLACKBOX_REPO_BRANCH set to another branch fetched that branch only into
    FETCH_HEAD, so `git checkout <branch>` failed ("resolve local changes") on
    every existing install — found upgrading two benches to the DKG 10.0.21
    branch on 2026-10-06. A file:// URL keeps --depth honoured, as on a real
    network clone (git ignores --depth for plain local paths)."""
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, capture_output=True)
    (source / "pyproject.toml").write_text("[project]\nname='agent-blackbox'\n")
    (source / "plugins" / "blackbox").mkdir(parents=True)
    (source / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n")
    _commit_all(source, "main")
    subprocess.run(["git", "checkout", "-q", "-b", "feat/next"], cwd=source, check=True)
    (source / "NEXT").write_text("the next release\n")
    _commit_all(source, "next")
    subprocess.run(["git", "checkout", "-q", "main"], cwd=source, check=True)
    install_dir = tmp_path / "agent-blackbox"

    first = _resolve_repo(install_dir, source, "main")
    assert first.returncode == 0, first.stderr
    assert not (install_dir / "NEXT").exists()

    switched = _resolve_repo(install_dir, source, "feat/next")

    assert switched.returncode == 0, switched.stderr
    head = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=install_dir,
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == "feat/next"
    assert (install_dir / "NEXT").read_text() == "the next release\n"

    again = _resolve_repo(install_dir, source, "feat/next")   # a later same-branch re-run still works
    assert again.returncode == 0, again.stderr


def _source_repo(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, capture_output=True)
    (source / "pyproject.toml").write_text("[project]\nname='agent-blackbox'\n")
    (source / "plugins" / "blackbox").mkdir(parents=True)
    (source / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n")
    _commit_all(source, "v1")
    return source


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
@_THROWAWAY_REPO_UPDATE
def test_shell_installer_updates_an_existing_install_when_its_branch_moved(tmp_path: Path) -> None:
    """KI-294: the install is a --depth 1 clone and the update fetched --depth 1
    too, so the new tip arrived without its parent; git saw no shared history
    ("ahead 1, behind 1") and `pull --ff-only` refused — every user upgrade by
    re-running the installer failed as soon as the branch had one new commit
    (bench native-c, 2026-10-07)."""
    source = _source_repo(tmp_path)
    install_dir = tmp_path / "agent-blackbox"
    assert _resolve_repo(install_dir, source, "main").returncode == 0
    (source / "RELEASE").write_text("v2\n")
    _commit_all(source, "v2")

    updated = _resolve_repo(install_dir, source, "main")

    assert updated.returncode == 0, updated.stderr
    assert (install_dir / "RELEASE").read_text() == "v2\n"


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
@_THROWAWAY_REPO_UPDATE
def test_shell_installer_never_discards_a_local_commit_when_updating(tmp_path: Path) -> None:
    """The update moves the install to the new tip only when the install holds no
    work of its own; a local commit makes it stop with git's reason instead."""
    source = _source_repo(tmp_path)
    install_dir = tmp_path / "agent-blackbox"
    assert _resolve_repo(install_dir, source, "main").returncode == 0
    (install_dir / "LOCAL").write_text("operator's own change\n")
    _commit_all(install_dir, "local work")
    (source / "RELEASE").write_text("v2\n")
    _commit_all(source, "v2")

    refused = _resolve_repo(install_dir, source, "main")

    assert refused.returncode != 0
    assert (install_dir / "LOCAL").exists()
    assert "not on that branch" in refused.stderr and "local work" in refused.stderr   # names the commit (KI-417)


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="requires git and bash",
)
@_THROWAWAY_REPO_UPDATE
def test_shell_installer_updates_a_checkout_moved_to_an_older_commit_of_the_branch(tmp_path: Path) -> None:
    """KI-417 (trader bench, 2026-10-15): the checkout had been moved, outside the installer,
    to a commit that IS on the branch but that the installer had not fetched last. The depth-1
    clone has no history to show that, git reported "diverged", and the installer refused with
    "it holds local commits" although it held none. It now fetches a bounded stretch of history,
    sees HEAD is part of the branch, and moves forward."""
    source = _source_repo(tmp_path)
    install_dir = tmp_path / "agent-blackbox"
    assert _resolve_repo(install_dir, source, "main").returncode == 0
    (source / "RELEASE").write_text("v2\n")
    _commit_all(source, "v2")
    subprocess.run(["git", "branch", "side"], cwd=source, check=True)             # side = v2
    (source / "RELEASE").write_text("v3\n")
    _commit_all(source, "v3")
    # the out-of-band move: fetch v2 by another branch name and check it out
    subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", "side"], cwd=install_dir, check=True)
    subprocess.run(["git", "reset", "-q", "--hard", "FETCH_HEAD"], cwd=install_dir, check=True)
    assert (install_dir / "RELEASE").read_text() == "v2\n"

    updated = _resolve_repo(install_dir, source, "main")

    assert updated.returncode == 0, updated.stderr
    assert (install_dir / "RELEASE").read_text() == "v3\n"


def test_powershell_installer_fetches_a_branch_with_an_explicit_refspec() -> None:
    """KI-287 mirror: the Windows installer must record origin/<branch> too."""
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert '"+refs/heads/${RepoBranch}:refs/remotes/origin/${RepoBranch}"' in text
    assert "remote set-branches --add origin $RepoBranch" in text


def test_powershell_installer_updates_like_the_shell_installer() -> None:
    """KI-294 mirror: the Windows installer moves a work-free install to the new tip."""
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert '$fetchedBefore = (& git -C $RepoDir rev-parse -q --verify "refs/remotes/origin/$RepoBranch"' in text
    assert '& git -C $RepoDir reset -q --keep "refs/remotes/origin/$RepoBranch"' in text


def test_powershell_installer_also_checks_history_before_refusing_an_update() -> None:
    """KI-417 mirror: the Windows installer moves a checkout that is already part of the branch
    forward (bounded history fetch) and names the commits when it does refuse."""
    text = INSTALL_PS1.read_text(encoding="utf-8")
    check = re.search(r"^function Test-BlackboxHeadInBranch \{\r?\n(?P<body>.*?)^\}", text, re.MULTILINE | re.DOTALL)
    assert check is not None
    assert '"--deepen=$HistoryCheckDepth"' in check["body"] and "merge-base --is-ancestor HEAD $remote" in check["body"]
    assert "$HistoryCheckDepth = 200" in text
    assert "-or (Test-BlackboxHeadInBranch)" in text
    assert "it holds commits that are not on that branch" in text
