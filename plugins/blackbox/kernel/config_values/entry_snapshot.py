"""The saved Blackbox entry as Hermes last merged it, kept for a short process that has not loaded
Hermes's config module — so a coding agent's hook judging a call itself does not pay for it.

WHY (Linux round L8, BB-LINUX-PENDING-7582d0, the hook budget): with the dashboard stopped the hook
runner judges each call in a fresh process, and on the 4-CPU VM at load 12 that took 5.0-6.6 s
(p50) against a 6.5 s budget. Profiled there (``python -X importtime``, py-spy), importing
``hermes_cli.config`` — only to read Blackbox's own settings — was the largest single cost of the
whole judgement: 272 ms of 986 ms of imports at load 6.

Every process that reads the entry through Hermes (the dashboard, Hermes itself) keeps
:data:`SNAPSHOT_NAME` current; a process without ``hermes_cli.config`` loaded reads it instead,
but ONLY while the files Hermes merged are exactly the ones it was made from: the snapshot carries
Hermes's own change key of the user's ``config.yaml`` and of the managed scope's ``config.yaml``
(``hermes_cli.config._load_config_cache_sig``: ``utils.file_signature`` of each — mtime, size,
inode, ctime), and any difference sends the reader to Hermes's merge as before. No snapshot is
kept when either file holds a ``${…}`` reference (Hermes expands those from the READING process's
environment, which differs between processes) or when Hermes answered its unreadable-file stand-in.

Security: the snapshot lives in Blackbox's data folder, which an agent may not change (read-only
inside the sandbox, a guarded place for every hook) — the same protection as the config itself.

Usage (``saved_entry`` only)::

    entry = entry_snapshot.read(config_path)          # None: read through Hermes
    key = entry_snapshot.signature(config_path)       # BEFORE that read (a change during it then misses)
    entry_snapshot.keep(key, config_path, entry)      # after a good read through Hermes
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

from .. import constants
from ..bounded_files import atomic_write, read_small_text

logger = logging.getLogger(__name__)

#: The file in Blackbox's data folder.
SNAPSHOT_NAME = "settings-snapshot.json"
#: The most read of it, and of a config file checked for ``${…}``.
MAX_SNAPSHOT_BYTES, MAX_CONFIG_BYTES = 256 * 1024, 4 * 1024 * 1024
#: Hermes's module whose presence means the process already pays for (and caches) the real merge.
HERMES_CONFIG_MODULE = "hermes_cli.config"
_written: dict[str, Any] = {"key": None}


def _path() -> Path:
    return constants.blackbox_home() / SNAPSHOT_NAME


def signature(config_path: Path) -> Optional[list[int]]:
    """Hermes's change key of the files its merge reads (user config, managed config); None when
    Hermes's helpers are not importable (no Hermes: nothing to cache)."""
    try:
        from hermes_cli import managed_scope   # light: Hermes's own seam for the managed folder
        from utils import file_signature
    except Exception:   # health: allow BLE001 -- standalone: read the config the slow way
        return None
    key: list[int] = []
    managed = managed_scope.get_managed_dir()
    for path in (config_path, managed / "config.yaml" if managed else None):
        try:
            key += list(file_signature(path.stat())) if path else [0, 0, 0, 0]
        except OSError:
            key += [0, 0, 0, 0]
    return key


def read(config_path: Path) -> Optional[dict[str, Any]]:
    """The entry as Hermes merged it from these very files, or None (read through Hermes)."""
    if HERMES_CONFIG_MODULE in sys.modules:
        return None   # the real merge is loaded and cached here: never second-guess it
    text = read_small_text(str(_path()), MAX_SNAPSHOT_BYTES, nofollow=True)
    key = signature(config_path) if text is not None else None
    if text is None or key is None:
        return None
    try:
        snapshot = json.loads(text)
    except ValueError:
        return None
    if not isinstance(snapshot, dict) or snapshot.get("key") != key or not isinstance(snapshot.get("entry"), dict):
        return None
    return snapshot["entry"]


def _expands(path: Optional[Path]) -> bool:
    text = read_small_text(str(path), MAX_CONFIG_BYTES) if path else None
    return text is None or "${" in text


def keep(key: Optional[list[int]], config_path: Path, entry: dict[str, Any]) -> None:
    """Save *entry* — read through Hermes from *config_path* after :func:`signature` answered *key* —
    for the processes that read :func:`read`. Writes only when it changed, only into an existing
    Blackbox home, and never when Hermes expanded ``${…}`` in those files."""
    if key is None or _written["key"] == (key, entry) or not constants.blackbox_home().is_dir():
        return
    try:
        from hermes_cli import managed_scope
        managed = managed_scope.get_managed_dir()
        if _expands(config_path) or (managed and (managed / "config.yaml").exists() and _expands(managed / "config.yaml")):
            _path().unlink(missing_ok=True)
            return
        atomic_write(_path(), json.dumps({"key": key, "entry": entry}), mode=0o600)
        _written["key"] = (key, entry)
    except (OSError, TypeError, ValueError):
        logger.debug("blackbox: the settings snapshot was not saved", exc_info=True)


__all__ = ["HERMES_CONFIG_MODULE", "SNAPSHOT_NAME", "keep", "read", "signature"]
