"""Which operating system a file of the plugin belongs to, so a copy carries only this machine's
(per-OS structure, Amos 2026-11-21).

The rule: inside a folder named ``platform``, an entry whose name (without its extension) is an
operating system's folder name — ``macos``, ``windows``, ``linux`` — belongs to that operating
system. Everything else (``mod.rs``, ``__init__.py``, ``unsupported.py``, …) belongs to every
system. A copy of the plugin (``blackbox attach``, the installer) leaves out what belongs to
another operating system, so a Mac's copy holds no Windows or Linux files.

Self-contained (standard library only) so the installer can load this one file by path.

Usage::

    shutil.copytree(src, dest, ignore=lambda folder, names: other_os_entries(folder, names))
    other_os_entries("…/monitor/platform", ["macos.py", "windows.py"], "darwin")   # ["windows.py"]
"""

from __future__ import annotations

import sys
from pathlib import PurePath
from typing import Iterable, Optional

#: The folder whose entries are sorted by operating system.
PLATFORM_FOLDER = "platform"
#: ``sys.platform`` prefix → that operating system's folder name.
OS_FOLDERS = {"darwin": "macos", "win32": "windows", "linux": "linux"}


def os_folder(sys_platform: Optional[str] = None) -> str:
    """The folder name of *sys_platform* (default: this machine's); "" for one with no folder yet."""
    here = sys.platform if sys_platform is None else sys_platform
    return next((name for prefix, name in OS_FOLDERS.items() if here.startswith(prefix)), "")


def other_os_entries(folder: str, names: Iterable[str], sys_platform: Optional[str] = None) -> list[str]:
    """The entries of *names* (in *folder*) that belong to another operating system — for a
    ``shutil.copytree`` ignore. Outside a ``platform`` folder: none."""
    if PurePath(folder).name != PLATFORM_FOLDER:
        return []
    here = os_folder(sys_platform)
    return [name for name in names if PurePath(name).stem in OS_FOLDERS.values() and PurePath(name).stem != here]


__all__ = ["OS_FOLDERS", "PLATFORM_FOLDER", "os_folder", "other_os_entries"]
