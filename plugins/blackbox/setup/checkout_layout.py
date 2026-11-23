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
  ``git -C <checkout> sparse-checkout add /apps/`` (then ``git sparse-checkout reapply``).
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
    # The installer, before the checkout exists (both files read with `git show HEAD:<path>`):
    #   python -I checkout_layout.py <os_layout/__init__.py> [sys.platform]
"""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType
from typing import Optional

#: The plugin's folder in the repository: other operating systems' files are left out under it.
PLUGIN_ROOT = "plugins/blackbox"
#: Top-level folders nothing reads at run time (see the module doc for each one's evidence).
DEVELOPER_ONLY = ("tests", "tests-js", "apps", "website", "docs", "evals", "contributors", ".github", "nix")
#: Folders inside a left-out one that Hermes does read at run time.
RUNTIME_INSIDE_DEVELOPER_ONLY = ("website/static/api",)


def checkout_patterns(layout: ModuleType, sys_platform: Optional[str] = None) -> list[str]:
    """The sparse-checkout lines for *sys_platform* (default: this machine), with *layout* the
    ``kernel.os_layout`` module (passed in so the installer can load it from a file by path)."""
    lines = ["/*"]
    lines += [f"!/{folder}/" for folder in DEVELOPER_ONLY]
    lines += [f"/{folder}/" for folder in RUNTIME_INSIDE_DEVELOPER_ONLY]
    lines.append(f"!/{PLUGIN_ROOT}/**/tests/")
    lines += layout.other_os_patterns(PLUGIN_ROOT, sys_platform)
    return lines


def patterns(sys_platform: Optional[str] = None) -> list[str]:
    """:func:`checkout_patterns` with the plugin's own ``kernel.os_layout``."""
    from ..kernel import os_layout
    return checkout_patterns(os_layout, sys_platform)


def _load(path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location("blackbox_os_layout", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    # The installer's way in: no package is installed yet, so os_layout comes from a file.
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: checkout_layout.py <os_layout/__init__.py> [sys.platform]")
    print("\n".join(checkout_patterns(_load(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else None)))
