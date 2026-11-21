"""Add-ons beside the plugin, and the places they ask the guard to protect from agents.

* :data:`ADDON_PACKAGES` — the add-on packages loaded through the shields extension point (a
  folder of each name next to the plugin's folder). The guard protects each one's folder in every
  Hermes home exactly as it protects the plugin's own: an agent that deletes an add-on removes
  protection (found on a fresh VM, 2026-11-21).
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

import os
import threading
from typing import Iterable

#: The add-on folders looked for next to the plugin's own folder, in load order.
ADDON_PACKAGES = ("blackbox_desktop",)

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
