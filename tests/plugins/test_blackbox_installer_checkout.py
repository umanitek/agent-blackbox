"""The installer's checkout holds only what this machine runs (``setup/checkout_layout.py``, the
installer's ``clone_this_machines_checkout`` / ``apply_checkout_layout``): Hermes and the plugin,
without the test suites, the docs site, Hermes Desktop's sources or another OS's files.

Security round 5 measured ``~/agent-blackbox`` at 929 MB / 138k files on a clean Mac, every other
operating system's platform code included (per-OS structure, 2026-11-21). The sparse patterns are
generated from ``kernel/os_layout`` — the rule ``blackbox attach`` copies by — and the drift test
below holds git's reading of them to that rule for every platform file in the repository (LES-137).

The clone tests run the installer's own functions against a LOCAL bare repository (no network):
a fresh clone, an update that must keep the set, and an older installer's full checkout converted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from plugins.blackbox.kernel import os_layout
from plugins.blackbox.setup import checkout_layout
from tests.plugins._blackbox_installer_shell import functions_with_callees

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
PLUGIN = REPO_ROOT / "plugins" / "blackbox"
#: The functions a test program calls; what they call comes with them (_blackbox_installer_shell).
CHECKOUT_FUNCTIONS = ("apply_checkout_layout", "clone_this_machines_checkout")
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
       "-c", "protocol.file.allow=always"]
#: Root folders and files the fixture repository carries besides the real plugin.
FIXTURE_FILES = ("pyproject.toml", "setup-hermes.sh", "hermes_cli/__init__.py", "tests/test_x.py",
                 "tests-js/a.test.js", "apps/desktop/package.json", "website/docs/intro.md",
                 "website/static/api/model-catalog.json", "docs/guide.md", "ui-tui/package.json", "web/package.json")


def _excluded_by_os_layout(path: str, sys_platform: str) -> bool:
    """os_layout's own answer for one repository path: some ``platform/`` entry on it is another OS's."""
    parts = PurePosixPath(path).parts
    return any(parts[i - 1] == os_layout.PLATFORM_FOLDER and os_layout.other_os_entries(
        os_layout.PLATFORM_FOLDER, [parts[i]], sys_platform) for i in range(1, len(parts)))


def _expected(path: str, sys_platform: str) -> bool:
    """Whether *path* belongs in this machine's checkout (the layout module's documented set)."""
    top = path.split("/", 1)[0]
    if path.startswith(tuple(f"{folder}/" for folder in checkout_layout.RUNTIME_INSIDE_DEVELOPER_ONLY)):
        return True
    if top in checkout_layout.DEVELOPER_ONLY:
        return False
    if path.startswith("plugins/blackbox/") and "tests" in PurePosixPath(path).parts:
        return False
    return not _excluded_by_os_layout(path, sys_platform)


# ── The patterns, per operating system ──────────────────────────────────────────────────────

@pytest.mark.parametrize("sys_platform, gone", [("darwin", {"windows", "linux"}), ("linux", {"macos", "windows"}),
                                                ("win32", {"macos", "linux"}), ("freebsd14", {"macos", "windows", "linux"})])
def test_each_os_leaves_out_every_other_os_and_keeps_its_own(sys_platform, gone):
    lines = checkout_layout.patterns(sys_platform)
    named = {line.rsplit("/", 1)[-1].split(".", 1)[0] for line in lines if "/platform/" in line}
    assert named == gone
    assert all(line.startswith("!/plugins/blackbox/") for line in lines if "/platform/" in line)
    assert lines[0] == "/*" and "!/tests/" in lines and "/website/static/api/" in lines


def test_the_installers_way_in_prints_the_same_lines_from_the_two_files(tmp_path):
    """The installer has no package yet: it runs checkout_layout.py by path with os_layout's file."""
    shutil.copy(PLUGIN / "kernel" / "os_layout" / "__init__.py", tmp_path / "os_layout.py")
    shutil.copy(PLUGIN / "setup" / "checkout_layout.py", tmp_path / "checkout_layout.py")
    for sys_platform in ("darwin", "linux", "win32"):
        done = subprocess.run([sys.executable, "-I", str(tmp_path / "checkout_layout.py"), str(tmp_path / "os_layout.py"),
                               sys_platform], capture_output=True, text=True, timeout=60, check=True)
        assert done.stdout.splitlines() == checkout_layout.patterns(sys_platform)


def test_a_platform_entry_with_more_than_one_dot_belongs_to_its_os():
    """git's "linux.*" covers linux.tar.gz; the copy rule reads the name up to its first dot to agree."""
    assert os_layout.other_os_entries("x/platform", ["linux.tar.gz", "linuxish.py", "macos.d"], "darwin") == ["linux.tar.gz"]


# ── Real git: a local bare repository, the installer's own functions ────────────────────────

def _git(*args: str, cwd: Path) -> str:
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, timeout=120, check=True).stdout


def _shell(call: str, *, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    functions = functions_with_callees(INSTALL_SH.read_text(encoding="utf-8"), CHECKOUT_FUNCTIONS)
    script = "\n".join(["set -euo pipefail", "GREEN= YELLOW= CYAN= RED= NC=", f'PY="{sys.executable}"', "VENV_DIR=", functions, call])
    env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "protocol.file.allow",
           "GIT_CONFIG_VALUE_0": "always", **(env_extra or {})}
    return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=300, env=env, check=False)


def _ignore(_folder: str, names: list[str]) -> list[str]:
    return [n for n in names if n in {"__pycache__", "target", "node_modules", ".pytest_cache"}]


@pytest.fixture(scope="module")
def origin(tmp_path_factory) -> Path:
    """A bare repository holding the real plugin (every OS's platform code) and a slice of the rest."""
    work = tmp_path_factory.mktemp("work")
    shutil.copytree(PLUGIN, work / "plugins" / "blackbox", ignore=_ignore)
    shutil.copy(REPO_ROOT / "plugins" / "__init__.py", work / "plugins" / "__init__.py")
    for name in FIXTURE_FILES:
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_text("{}\n" if name.endswith(".json") else "# fixture\n", encoding="utf-8")
    # The tree must carry every OS's files for the test to mean anything.
    for os_name in ("linux", "windows"):
        stub = work / "plugins" / "blackbox" / "shields" / "network" / "monitor" / "platform" / f"{os_name}.py"
        stub.write_text("raise ImportError('another OS')\n", encoding="utf-8")
    _git("init", "-q", cwd=work)
    _git("add", "-A", cwd=work)
    _git("commit", "-q", "-m", "fixture", cwd=work)
    bare = tmp_path_factory.mktemp("origin") / "agent-blackbox.git"
    # --no-local: objects copied through git's own transfer, never hard-linked to the work tree's.
    _git("clone", "-q", "--bare", "--no-local", str(work), str(bare), cwd=work)
    _git("config", "gc.auto", "0", cwd=bare)
    _git("config", "uploadpack.allowFilter", "true", cwd=bare)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=bare)
    return bare


def _tracked(repo: Path) -> list[str]:
    return _git("ls-tree", "-r", "--name-only", "HEAD", cwd=repo).splitlines()


def _present(repo: Path) -> set[str]:
    return {p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file() and ".git" not in p.relative_to(repo).parts}


def _clone(origin: Path, dest: Path, sys_platform: str) -> subprocess.CompletedProcess:
    return _shell(f'clone_this_machines_checkout "file://{origin}" main "{dest}"',
                  env_extra={"BLACKBOX_CHECKOUT_OS": sys_platform})


@pytest.mark.parametrize("sys_platform", ["darwin", "linux", "win32"])
def test_a_fresh_clone_holds_exactly_this_machines_set(origin, tmp_path, sys_platform):
    """Drift test (LES-137): git's reading of the generated patterns equals os_layout's rule (and the
    documented developer-only folders) for every file of the repository."""
    dest = tmp_path / "agent-blackbox"
    done = _clone(origin, dest, sys_platform)
    assert done.returncode == 0, done.stderr
    expected = {path for path in _tracked(dest) if _expected(path, sys_platform)}
    assert _present(dest) == expected
    others = {"darwin": ("windows", "linux"), "linux": ("macos", "windows"), "win32": ("macos", "linux")}[sys_platform]
    assert not [p for p in _present(dest) if any(f"/platform/{name}" in p for name in others)]
    assert "website/static/api/model-catalog.json" in _present(dest) and "pyproject.toml" in _present(dest)
    assert not any(p.startswith(("tests/", "apps/", "website/docs/")) for p in _present(dest))
    assert _git("config", "remote.origin.promisor", cwd=dest).strip() == "true"   # a partial (blobless) clone


def test_the_plugin_imports_from_this_machines_checkout(origin, tmp_path):
    dest = tmp_path / "agent-blackbox"
    assert _clone(origin, dest, sys.platform).returncode == 0
    facades = ["plugins.blackbox.notify.platform", "plugins.blackbox.setup.platform",
               "plugins.blackbox.shields.network.monitor.platform", "plugins.blackbox.shields.files.sandbox.platform",
               "plugins.blackbox.agent_hooks.observe.platform"]
    # The checkout comes first; the real repository last, for Hermes's own modules the plugin imports
    # (utils, agent, hermes_cli), which the fixture leaves out. The interpreter that runs the suite
    # need not have them installed, so they are named here rather than assumed.
    code = ("import importlib, sys; sys.path.insert(0, sys.argv[1]); sys.path.append(sys.argv[2]); "
            "import plugins.blackbox as bb; "
            "assert bb.__file__.startswith(sys.argv[1]), bb.__file__; "
            "[importlib.import_module(name) for name in sys.argv[3:]]; print('imported')")
    done = subprocess.run([sys.executable, "-c", code, str(dest), str(REPO_ROOT), *facades], capture_output=True, text=True,
                          timeout=300, cwd=tmp_path, check=False)
    assert done.returncode == 0 and "imported" in done.stdout, done.stderr[-3000:]


def test_an_update_keeps_the_same_set(origin, tmp_path):
    """The installer's update: fetch, re-apply the set from the new commit, move the tree."""
    dest = tmp_path / "agent-blackbox"
    assert _clone(origin, dest, "darwin").returncode == 0
    work = tmp_path / "work"
    _git("clone", "-q", str(origin), str(work), cwd=tmp_path)
    (work / "tests" / "test_new.py").write_text("# new\n", encoding="utf-8")
    (work / "plugins" / "blackbox" / "notify" / "platform" / "windows.py").write_text("# new\n", encoding="utf-8")
    (work / "plugins" / "blackbox" / "kernel" / "new_runtime_file.txt").write_text("new\n", encoding="utf-8")
    _git("add", "-A", cwd=work)
    _git("commit", "-q", "-m", "update", cwd=work)
    _git("push", "-q", "origin", "main", cwd=work)
    done = _shell(f'git -C "{dest}" fetch -q --depth 1 origin main && '
                  f'apply_checkout_layout "{dest}" refs/remotes/origin/main && '
                  f'git -C "{dest}" reset -q --keep refs/remotes/origin/main', env_extra={"BLACKBOX_CHECKOUT_OS": "darwin"})
    assert done.returncode == 0, done.stderr
    present = _present(dest)
    assert "plugins/blackbox/kernel/new_runtime_file.txt" in present
    assert "tests/test_new.py" not in present and "plugins/blackbox/notify/platform/windows.py" not in present
    assert present == {path for path in _tracked(dest) if _expected(path, "darwin")}


def test_an_older_installers_full_checkout_is_converted_and_local_changes_stay(origin, tmp_path):
    dest = tmp_path / "agent-blackbox"
    _git("clone", "-q", "--depth", "1", f"file://{origin}", str(dest), cwd=tmp_path)   # the old installer's clone
    assert "tests/test_x.py" in _present(dest)
    changed = dest / "apps" / "desktop" / "package.json"
    changed.write_text('{"mine": true}\n', encoding="utf-8")
    done = _shell(f'apply_checkout_layout "{dest}" HEAD', env_extra={"BLACKBOX_CHECKOUT_OS": "darwin"})
    assert done.returncode == 0, done.stderr
    present = _present(dest)
    assert "tests/test_x.py" not in present and "plugins/blackbox/shields/network/monitor/platform/linux.py" not in present
    assert changed.read_text(encoding="utf-8") == '{"mine": true}\n'   # git never drops a local change
    assert present - {"apps/desktop/package.json"} == {path for path in _tracked(dest) if _expected(path, "darwin")}


def test_without_a_python_the_whole_checkout_is_kept_and_said(origin, tmp_path):
    """No Python 3.8+ yet: the clone still completes (narrowed later, after Hermes's setup)."""
    dest = tmp_path / "agent-blackbox"
    # Defined after the extracted bodies, this stand-in wins: no Python on the machine.
    done = _shell(f'checkout_layout_python() {{ return 1; }}; clone_this_machines_checkout "file://{origin}" main "{dest}"')
    assert done.returncode == 0, done.stderr
    assert "downloading the whole checkout" in done.stdout
    assert _present(dest) == set(_tracked(dest))
