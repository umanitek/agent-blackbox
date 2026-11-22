"""Blackbox's saved settings entry (``plugins.entries.blackbox`` in the main Hermes ``config.yaml``).

:func:`read` is what :func:`..config._blackbox_entry` answers: the entry as a mapping, ``{}`` on
any error. Read from the machine's MAIN Hermes config (:func:`..constants.hermes_root`) even while
a named profile runs: one set of Blackbox settings protects every profile, and what the dashboard
saves reaches them all (a profile used to keep the copy made when it was created).
"""

from __future__ import annotations

import logging
from typing import Any

from .. import constants, yaml_files

logger = logging.getLogger(__name__)


def read() -> dict[str, Any]:
    """The saved Blackbox entry (``{}`` on any error)."""
    root = constants.hermes_root()
    if root != constants.hermes_home():
        return yaml_files.blackbox_entry(yaml_files.load_yaml(root / "config.yaml"))
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("blackbox: config load failed (%s); using defaults", exc)
        return {}
    return yaml_files.blackbox_entry(cfg)
