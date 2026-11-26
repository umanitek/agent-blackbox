"""Add-ons beside the plugin, and the places they ask the guard to protect from agents.

* :data:`MANIFEST` / :func:`found` / :func:`folders` — how an add-on is recognised. The plugin
  names no add-on: an add-on is any package folder next to the plugin's folder that ships a
  manifest file, ``blackbox-addon.json``, holding ``{"extends": "blackbox"}``. The shields
  extension point loads each one found; the guard protects each one's folder in every Hermes home
  exactly as it protects the plugin's own (an agent that deletes an add-on removes protection;
  found on a fresh VM, 2026-11-21), and protects the manifest name itself, so an agent can neither
  plant an add-on nor remove one by deleting its manifest.
* :func:`declare` / :func:`places` / :func:`editable_configs` — more places an installed add-on
  declares at run time (below).

The plugin's self-protection (:mod:`..detection.paths.guard_places`) knows Blackbox's own places.
An add-on loaded through the shields extension point (``Registrar.protect_places``) brings places
of its own — its data folder, a helper's folder, the hook configs it writes into other programs —
and declares them here, so the same deny-by-reference rule guards them without the plugin naming
the add-on. A Registry pattern: a tiny, thread-safe store that only grows during one process.

* ``places`` — absolute patterns (``*`` allowed): any write, move or delete there is refused;
* ``editable_configs`` — file names among those places that belong to ANOTHER program (an agent's
  own settings file): an edit there is refused only when it touches Blackbox's part of the file,
  as the guard already treats Hermes' ``config.yaml``.

Usage (an add-on's ``register``)::

    registrar.protect_places(["~/Library/Application Support/Example"], editable_configs=["settings.json"])
"""

from __future__ import annotations

import glob
import json
import os
import threading
from pathlib import Path
from typing import Iterable

from ..bounded_files import read_small_text

#: The file an add-on ships at the top of its package folder to declare itself an add-on.
MANIFEST = "blackbox-addon.json"
#: What the manifest's ``extends`` must say.
EXTENDS = "blackbox"
#: The largest manifest read (it holds one small JSON object).
MAX_MANIFEST_BYTES = 4096
#: The most add-on folders one plugins folder (or pattern) yields.
MAX_ADDONS = 20
#: The plugin's own folder name: never an add-on of itself.
PLUGIN_FOLDER = "blackbox"

def declares(folder: Path) -> bool:
    """True when *folder* is an add-on: an importable package name (not the plugin's own), an
    ``__init__.py`` and a manifest whose ``extends`` is :data:`EXTENDS`."""
    if not folder.name.isidentifier() or folder.name == PLUGIN_FOLDER or not (folder / "__init__.py").is_file():
        return False
    text = read_small_text(str(folder / MANIFEST), MAX_MANIFEST_BYTES, nofollow=True)
    try:
        manifest = json.loads(text) if text is not None else None
    except ValueError:
        return False
    return isinstance(manifest, dict) and manifest.get("extends") == EXTENDS


def found(plugins_dir: Path) -> tuple[str, ...]:
    """The add-on folder names in *plugins_dir*, sorted (the load order)."""
    return tuple(Path(folder).name for folder in folders(str(plugins_dir)))


def folders(plugins_dir: str) -> tuple[str, ...]:
    """The add-on folders in *plugins_dir* — a folder, or a pattern with ``*`` (every profile's
    plugins folder) — as sorted absolute paths, at most :data:`MAX_ADDONS` per call."""
    # A plain folder is escaped so a "[" in a real path is not read as a pattern.
    base = plugins_dir if any(char in plugins_dir for char in "*?[") else glob.escape(plugins_dir)
    try:
        manifests = sorted(glob.glob(os.path.join(base, "*", MANIFEST)))
    except (OSError, ValueError):
        return ()
    addon_folders = [os.path.dirname(manifest) for manifest in manifests]
    return tuple(folder for folder in addon_folders if declares(Path(folder)))[:MAX_ADDONS]


def manifest_pattern(plugins_dir: str) -> str:
    """The pattern of every add-on manifest in *plugins_dir* (for the guard: no agent writes one)."""
    return os.path.join(plugins_dir, "*", MANIFEST)


_lock = threading.Lock()
_places: list[str] = []
_editable: set[str] = set()
_version = 0
#: The most places one process keeps (a runaway add-on cannot make every check slow).
MAX_PLACES = 200


def declare(places: Iterable[str], editable_configs: Iterable[str] = ()) -> None:
    """Adds *places* (``~`` expanded; relative ones ignored) and *editable_configs* (bare file names)."""
    global _version
    with _lock:
        for place in places:
            path = os.path.expanduser(str(place or "").strip())
            if os.path.isabs(path) and path not in _places and len(_places) < MAX_PLACES:
                _places.append(os.path.normpath(path))
        _editable.update(name for name in (os.path.basename(str(n)) for n in editable_configs) if name)
        _version += 1


def places() -> tuple[str, ...]:
    with _lock:
        return tuple(_places)


def editable_configs() -> frozenset[str]:
    with _lock:
        return frozenset(_editable)


def version() -> int:
    """Changes whenever something is declared: callers that keep a reading re-read on a change."""
    with _lock:
        return _version


def clear() -> None:
    """Forgets every declaration (tests, and a reloaded plugin)."""
    global _version
    with _lock:
        _places.clear()
        _editable.clear()
        _version += 1
