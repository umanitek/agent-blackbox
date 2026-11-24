"""Empty placeholders for the startup places that do not exist yet (design "Linux deep layers"
§1.3, founder decision F1). A mount needs something to cover, so a place missing when an agent
starts is NOT closed inside — and an agent could create ``~/.config/systemd/user/evil.service``.
Blackbox therefore creates, in the person's home only:

* every missing startup FOLDER (empty, mode 0700) — an empty folder starts nothing;
* the missing startup FILES whose empty form is a no-op (:data:`NOOP_FILES`: zsh's files,
  ``.bashrc``, ``.bash_logout``, ``.xprofile``, ``.xsessionrc``, ``.pam_environment``, the
  authorized-keys files). Never ``.bash_profile`` / ``.bash_login``: one of them existing stops
  bash from reading ``.profile``. Those (and the rest) stay hooks + the real-time watch only.

Each placeholder made is recorded (:data:`MANIFEST`), so an uninstall removes the ones still empty
and nothing else.

Usage::

    made = ensure(places, home, manifest_path)     # the placeholders created now
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ......kernel.bounded_files import atomic_write, read_small_text
from ...places import Places

MANIFEST = "placeholders.json"
#: Startup files, relative to home, whose empty form changes nothing.
#: ``.config/mimeapps.list`` too (KI-672): an empty one names no default application, and a missing
#: one could be CREATED inside to make the desktop open a file type or a link with an agent's program.
NOOP_FILES = (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".bashrc", ".bash_logout", ".xprofile",
              ".xsessionrc", ".pam_environment", ".ssh/authorized_keys", ".ssh/authorized_keys2", ".config/mimeapps.list")
MAX_MANIFEST_BYTES = 256 * 1024


def _inside(path: str, home: str) -> bool:
    return path.startswith(home.rstrip("/") + "/")


def wanted(places: Places, home: str) -> tuple[list[str], list[str]]:
    """``(folders, files)`` placeholders *places* needs in *home* (missing ones only)."""
    folders = [path for path in places.startup_folders if _inside(path, home) and not os.path.lexists(path)]
    noop = {os.path.join(home.rstrip("/"), name) for name in NOOP_FILES}
    files = [path for path in (*places.startup_files, *places.no_write_files) if path in noop and not os.path.lexists(path)]
    return list(dict.fromkeys(folders)), list(dict.fromkeys(files))


def recorded(manifest: Path) -> list[str]:
    """The placeholders Blackbox made so far."""
    try:
        rows = json.loads(read_small_text(str(manifest), MAX_MANIFEST_BYTES) or "[]")
    except ValueError:
        return []
    return [row for row in rows if isinstance(row, str)] if isinstance(rows, list) else []


def ensure(places: Places, home: str, manifest: Path) -> list[str]:
    """Creates the placeholders *places* needs and records them in *manifest*; answers the new ones.
    Fail-open: one that can not be made is skipped (the hooks and the watch still cover it)."""
    folders, files = wanted(places, home)
    made = []
    for folder in folders:
        try:
            os.makedirs(folder, mode=0o700)
            made.append(folder)
        except OSError:
            continue
    for path in files:
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            with open(path, "x", encoding="utf-8"):
                pass
            made.append(path)
        except OSError:
            continue
    if made:
        atomic_write(manifest, json.dumps(list(dict.fromkeys(recorded(manifest) + made))), mode=0o644)
    return made


__all__ = ["MANIFEST", "NOOP_FILES", "ensure", "recorded", "wanted"]
