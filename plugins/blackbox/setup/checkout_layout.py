"""What the installer's checkout of the repository holds on this machine: Hermes (the host) and the
plugin, without what only a developer uses and without another operating system's files.

The installer (``blackbox-install.sh`` / ``.ps1``) clones with ``--filter=blob:none`` and a sparse
checkout (git's non-cone patterns, the classic ``.git/info/sparse-checkout`` file — the form
Hermes's own subdirectory plugin installs use too, ``hermes_cli/plugins_cmd_git.py``). The
patterns are printed by this module, so the one list below and ``kernel/os_layout``'s rule decide
it; ``git pull`` / ``git reset`` keep the same set on every update, and an existing full checkout
is converted by writing the same file and re-applying it (files with local changes stay).

What is left out, and why each is safe (measured 2026-11-23 on feat/network-shield: 19,956 files /
230 MB tracked; this set is about 7,600 files / 96 MB, plus another OS's files):

* ``tests/`` and ``tests-js/`` — the test suites. pm's test environment (setup-hermes.sh
  ``--test-environment``) is built from ``pyproject.toml``/``uv.lock``, not from this folder; npm
  tolerates a missing workspace folder when an install names its workspaces (node-deps.mjs does).
* ``apps/`` — Hermes Desktop's sources, built only by ``hermes desktop`` (``main_desktop.py``), which
  this installer never sets up; every other reader checks for the folder first. Add it back with
  ``git -C <checkout> sparse-checkout add /apps/`` (then ``git sparse-checkout reapply``). EXCEPT the
  npm workspaces a kept workspace builds from (KI-653: ``ui-tui`` and ``web`` import
  ``@hermes/shared`` from ``apps/shared``; without it ``hermes --tui`` and ``hermes dashboard`` did
  not build). Those are not listed by hand: :func:`needed_workspaces` reads the root
  ``package.json`` ``workspaces`` and each workspace's ``package.json`` from the commit, follows the
  dependencies of every kept workspace (a ``file:`` path or a workspace's package name) and keeps
  every left-out folder in that closure.
* ``website/`` except ``website/static/api/`` — the docs site; Hermes reads only
  ``website/static/api/model-catalog.json`` at run time (``hermes_cli/model_catalog.py``).
* ``docs/``, ``evals/``, ``contributors/``, ``.github/``, ``nix/`` — documentation, benchmarks, the
  contributor list, CI and Nix packaging: nothing at run time reads them.
* the plugin's own ``tests/`` folders (the helper crate's), which ``blackbox attach`` never copies.

Kept although large: ``web/`` and ``ui-tui/`` (Hermes builds its dashboard and TUI from them),
``optional-skills/``, ``skills/``, ``locales/``, ``plugin-catalog/``, ``optional-mcps/``, ``scripts/``
(``run-in-hermes-env``, the node build scripts) and every root file (``setup.py`` derives the root
modules from the tree).

Usage::

    patterns()                       # this machine's lines, for .git/info/sparse-checkout
    patterns("linux")                # another machine's (tests)
    needed_workspaces(FolderTree("."))   # -> ["apps/shared"]
    # The installer, before the checkout exists (both files read with `git show HEAD:<path>`):
    #   python -I checkout_layout.py <os_layout/__init__.py> [sys.platform] --repo <clone> --rev <commit>
"""

from __future__ import annotations

import fnmatch
import importlib.util
import json
import posixpath
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Optional, Protocol

#: The plugin's folder in the repository: other operating systems' files are left out under it.
PLUGIN_ROOT = "plugins/blackbox"
#: Top-level folders nothing reads at run time (see the module doc for each one's evidence).
DEVELOPER_ONLY = ("tests", "tests-js", "apps", "website", "docs", "evals", "contributors", ".github", "nix")
#: Folders inside a left-out one that Hermes does read at run time.
RUNTIME_INSIDE_DEVELOPER_ONLY = ("website/static/api",)
#: The package.json fields whose packages a workspace builds with.
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
#: The longest one ``git show`` / ``git ls-tree`` may take (a partial clone fetches the blob).
GIT_TIMEOUT_SECONDS = 120
#: The repository this file sits in, when it is a checkout (``plugins/blackbox/setup/`` → root).
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class Tree(Protocol):
    """Read access to one commit's files (repository-relative POSIX paths)."""

    def text(self, path: str) -> Optional[str]:
        """The file's text, ``None`` when there is no such file."""

    def folders(self, path: str) -> list[str]:
        """The names of the folders directly inside *path* ("" is the root)."""


class GitTree:
    """A commit read with ``git show`` / ``git ls-tree`` — the installer's way in, before anything is
    checked out (a ``--filter=blob:none`` clone fetches the few blobs it reads)."""

    def __init__(self, repo: str, rev: str) -> None:
        self.repo, self.rev = repo, rev

    def _git(self, *args: str) -> Optional[str]:
        done = subprocess.run(["git", "-C", self.repo, *args], capture_output=True, text=True, encoding="utf-8-sig",
                              timeout=GIT_TIMEOUT_SECONDS, check=False)
        return done.stdout if done.returncode == 0 else None

    def text(self, path: str) -> Optional[str]:
        return self._git("show", f"{self.rev}:{path}")

    def folders(self, path: str) -> list[str]:
        listing = self._git("ls-tree", "-d", "--name-only", f"{self.rev}:{path}" if path else self.rev)
        return [line for line in (listing or "").splitlines() if line]


class FolderTree:
    """A working tree on disk (a developer's checkout, tests)."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)

    def text(self, path: str) -> Optional[str]:
        file = self.root / path
        return file.read_text(encoding="utf-8-sig") if file.is_file() else None   # a BOM from Windows tools is not JSON

    def folders(self, path: str) -> list[str]:
        folder = self.root / path
        return sorted(entry.name for entry in folder.iterdir() if entry.is_dir()) if folder.is_dir() else []


def _manifest(tree: Tree, folder: str) -> dict[str, object]:
    text = tree.text(f"{folder}/package.json" if folder else "package.json")
    try:
        value = json.loads(text) if text else {}
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _workspace_folders(tree: Tree) -> list[str]:
    """The folders the root ``package.json`` names as npm workspaces (``apps/*`` expanded)."""
    declared = _manifest(tree, "").get("workspaces", [])
    if isinstance(declared, dict):   # npm's {"packages": [...]} form
        declared = declared.get("packages", [])
    found: list[str] = []
    for pattern in declared if isinstance(declared, list) else []:
        bases = [""]
        for part in str(pattern).strip("/").split("/"):
            bases = [f"{base}/{name}".lstrip("/") for base in bases
                     for name in (fnmatch.filter(tree.folders(base), part) if any(c in part for c in "*?[") else [part])]
        found += [base for base in bases if tree.text(f"{base}/package.json") is not None]
    return list(dict.fromkeys(found))


def _left_out(folder: str) -> bool:
    return folder.split("/", 1)[0] in DEVELOPER_ONLY and not any(
        folder == kept or folder.startswith(kept + "/") for kept in RUNTIME_INSIDE_DEVELOPER_ONLY)


def needed_workspaces(tree: Tree) -> list[str]:
    """The left-out workspace folders a kept workspace depends on, directly or through another
    (the dependency closure over ``dependencies`` / ``devDependencies`` / ``peerDependencies`` /
    ``optionalDependencies``, by ``file:`` path or workspace package name), sorted."""
    folders = _workspace_folders(tree)
    manifests = {folder: _manifest(tree, folder) for folder in folders}
    by_name = {str(manifest.get("name")): folder for folder, manifest in manifests.items() if manifest.get("name")}
    todo = [folder for folder in folders if not _left_out(folder)]
    reached = set(todo)
    while todo:
        owner = todo.pop()
        manifest = manifests.get(owner, {})
        for field in DEPENDENCY_FIELDS:
            deps = manifest.get(field) if isinstance(manifest.get(field), dict) else {}
            for name, spec in deps.items():
                target = by_name.get(name)
                if isinstance(spec, str) and spec.startswith("file:"):
                    target = posixpath.normpath(posixpath.join(owner, spec[len("file:"):]))
                if target and target in manifests and target not in reached:
                    reached.add(target)
                    todo.append(target)
    return sorted(folder for folder in reached if _left_out(folder))


def checkout_patterns(layout: ModuleType, sys_platform: Optional[str] = None, tree: Optional[Tree] = None) -> list[str]:
    """The sparse-checkout lines for *sys_platform* (default: this machine), with *layout* the
    ``kernel.os_layout`` module (passed in so the installer can load it from a file by path) and
    *tree* the commit whose npm workspaces are read (:func:`needed_workspaces`; none: not read)."""
    lines = ["/*"]
    lines += [f"!/{folder}/" for folder in DEVELOPER_ONLY]
    lines += [f"/{folder}/" for folder in RUNTIME_INSIDE_DEVELOPER_ONLY]
    lines += [f"/{folder}/" for folder in (needed_workspaces(tree) if tree is not None else [])]
    lines.append(f"!/{PLUGIN_ROOT}/**/tests/")
    lines += layout.other_os_patterns(PLUGIN_ROOT, sys_platform)
    return lines


def patterns(sys_platform: Optional[str] = None, tree: Optional[Tree] = None) -> list[str]:
    """:func:`checkout_patterns` with the plugin's own ``kernel.os_layout``; *tree* defaults to the
    repository this plugin sits in, when it sits in one."""
    from ..kernel import os_layout
    if tree is None and (REPOSITORY_ROOT / "package.json").is_file():
        tree = FolderTree(str(REPOSITORY_ROOT))
    return checkout_patterns(os_layout, sys_platform, tree)


def _load(path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location("blackbox_os_layout", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


USAGE = "usage: checkout_layout.py <os_layout/__init__.py> [sys.platform] [--repo <git folder> --rev <commit>]"


def main(argv: list[str]) -> int:
    """The installer's way in: no package is installed yet, so os_layout comes from a file, and the
    commit's workspaces are read from the clone with git."""
    tree: Optional[Tree] = None
    if "--repo" in argv:
        at = argv.index("--repo")
        if argv[at + 2:at + 3] != ["--rev"] or len(argv) < at + 4:
            raise SystemExit(USAGE)
        tree = GitTree(argv[at + 1], argv[at + 3])
        argv = argv[:at] + argv[at + 4:]
    if len(argv) not in (1, 2):
        raise SystemExit(USAGE)
    print("\n".join(checkout_patterns(_load(argv[0]), argv[1] if len(argv) == 2 else None, tree)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
