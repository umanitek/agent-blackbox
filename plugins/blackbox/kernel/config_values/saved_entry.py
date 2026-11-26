"""Blackbox's saved settings entry (``plugins.entries.blackbox`` in the main Hermes ``config.yaml``).

:func:`read` is what :func:`..config._blackbox_entry` answers. Read from the machine's MAIN Hermes
config (:func:`..constants.hermes_root`) even while a named profile runs: one set of Blackbox
settings protects every profile, and what the dashboard saves reaches them all.

When the file cannot be read (an installer rewriting it while a dashboard restarts, a parse
error), the entry read last in this process stands in, so a passing read failure never flips
Blackbox's mode — Block stays Block. Before any good read there is nothing to stand in: the
answer is an :class:`UnreadEntry` (empty), and :func:`known` is False, so a status route says
"starting" instead of presenting the defaults (Audit, nothing blocked) as the person's settings.
WHY (KI-PENDING-b28f8f, VM pass 3, 2026-11-22): a companion app's Overview said "Audit mode … nothing is
blocked yet" while ``blackbox status`` said block, during a dashboard restart.

Pattern: a small **Memento** — the last good read kept for the failures after it.
"""

from __future__ import annotations

import copy
import logging
from typing import Any, Optional

from .. import constants, yaml_files
from . import entry_snapshot

logger = logging.getLogger(__name__)

_last: dict[str, Optional[dict[str, Any]]] = {"entry": None}


class UnreadEntry(dict):
    """The empty entry answered when the saved settings could not be read and none were read
    before in this process: defaults stand in, and they are not the person's settings."""


def _hermes_config() -> Any:
    """Hermes's merged config (config.yaml + managed scope, cached on the files' signature). WHY the
    read-only form (Linux round L7, BB-LINUX-PENDING-88f30f): ``load_config`` deep-copies the WHOLE
    config on every call and this read runs on most dashboard requests and every hook judgement —
    profiled on the busy VM it was about a tenth of the dashboard's CPU. Hermes older than
    ``load_config_readonly`` falls back to ``load_config``."""
    from hermes_cli import config as hermes_config

    reader = getattr(hermes_config, "load_config_readonly", None) or hermes_config.load_config
    return reader()


def _read_now() -> Optional[dict[str, Any]]:
    """The entry as saved now, or None when the config cannot be read."""
    root = constants.hermes_root()
    if root != constants.hermes_home():
        try:
            return yaml_files.blackbox_entry(yaml_files.load_for_edit(root / "config.yaml"))
        except yaml_files.UnreadableYaml as exc:
            logger.debug("blackbox: %s", exc)
            return None
    config_path = root / "config.yaml"
    kept = entry_snapshot.read(config_path)   # a hook's own process: Hermes's merge, without its import (L8)
    if kept is not None:
        return kept
    key = entry_snapshot.signature(config_path)
    try:
        cfg = _hermes_config()
    except Exception as exc:  # health: allow BLE001 -- an unreadable config is answered below, never raised
        logger.debug("blackbox: config load failed (%s)", exc)
        return None
    # Only Blackbox's own entry is copied: the read-only config is Hermes's cached object.
    entry = copy.deepcopy(yaml_files.blackbox_entry(cfg))
    # Hermes' stand-in for an unreadable file: its last-known-good copy (it holds the entry: the
    # person's settings, read before) or its defaults (no entry: nothing was read).
    if type(cfg).__name__ == "FailedConfigRead":
        return entry or None
    entry_snapshot.keep(key, config_path, entry)
    return entry


def read() -> dict[str, Any]:
    """The saved Blackbox entry; the last good one when it cannot be read now; an
    :class:`UnreadEntry` when it never could be in this process."""
    entry = _read_now()
    if entry is None:
        last = _last["entry"]
        return dict(last) if last is not None else UnreadEntry()
    _last["entry"] = dict(entry)
    return entry


def known(entry: dict[str, Any]) -> bool:
    """True when *entry* (what :func:`read` answered) holds the person's settings."""
    return not isinstance(entry, UnreadEntry)


def forget() -> None:
    """Tests: no read has happened in this process."""
    _last["entry"] = None
