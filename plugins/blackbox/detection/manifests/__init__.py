"""Dependency files: what an install installs when its command names no package (KI-595).

Blackbox once checked only the package names written in an install command. An install that
takes its packages from a manifest or lockfile (``npm ci``, ``uv sync``, ``pip install -r``,
``bundle install``), and the transitive dependencies a named install pulls in, were never
checked against the threat graph. This sub-package reads those files — one reader per format
(Strategy, :mod:`.registry`), pure, bounded, no network, cached — and judges every package with
the same ruleset lookup a named install uses.

* :func:`check_install_files` — before a call: the files a manifest install installs from.
* :func:`check_landed` — after a call: what an install added to its lockfile.
* :func:`check_dependency_write` — before a write: what a write adds to such a file.
* :func:`install_sites` — the installs a command runs and their folders.

Usage::

    from .manifests import check_install_files
    check = check_install_files(tool_name, args, ruleset)   # .findings, .notes
"""

from __future__ import annotations

from .checks import DependencyCheck, check_dependency_write, check_install_files, check_landed
from .commands import InstallSite, install_sites
from .registry import MAX_FILE_BYTES

__all__ = ["MAX_FILE_BYTES", "DependencyCheck", "InstallSite", "check_dependency_write", "check_install_files",
           "check_landed", "install_sites"]
