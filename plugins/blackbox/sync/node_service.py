"""The service manager registered to supervise this install's DKG node, and how to go through it.

The installer registers the node as a boot service: a systemd unit (``blackbox-dkg``, system or
user scope) on Linux, a LaunchAgent (``ai.umanitek.blackbox-dkg``) on macOS. Anything that
restarts the node must go through that service — a node started behind it is one the service
cannot supervise, and on macOS launchd's own copy then fails "Daemon already running" and is
relaunched for ever (KI-414, KI-426).

The service is found by REGISTRATION, not by inspecting a running process: when the node is down
(stopped for a restart, or crashed) there is no process to inspect, and that is exactly when a
caller would otherwise start an unsupervised copy. A registration counts only when its start
command is THIS install's DKG CLI (``cfg.dkg_bin``) — directly, or through the Blackbox launcher the
installer puts in front of it (KI-529: reading only the first argument missed the launcher, so every
macOS sync restarted the node behind launchd) — so another install's service is never touched.

Strategy pattern: :class:`NodeService` holds one manager's way of answering "which process do you
run?" and "restart it"; each ``sync/platform/<os>`` module builds its own (KI-628) and
:func:`registered` asks this machine's.

Usage::

    service = node_service.registered(cfg)
    if service is not None and not service.owns(node_pid):
        ...stop the stray copy first...
    if service is not None:
        service.restart()
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from ..kernel.config import BlackboxConfig
from . import platform as os_platform
from .platform.model import (DASHBOARD_LAUNCHD_LABEL, DASHBOARD_SYSTEMD_UNIT, LAUNCHD_LABEL, LAUNCHD_LABELS,
                             SYSTEM_UNIT_DIR, SYSTEMD_UNIT, SYSTEMD_UNITS, WINDOWS_TASKS, NodeService)

logger = logging.getLogger(__name__)

# launchd keeps no journal, so the installer sends the LaunchAgent node's stderr here (in the node's
# home, = blackbox_dkg_launchd_error_log in the installer). The node writes its warnings there too,
# a few MB a day, so it is trimmed in place: launchd holds it open for appending, and a replaced
# file would leave launchd writing into a deleted one.
LAUNCHD_ERROR_LOG = "launchd-errors.log"
ERROR_LOG_MAX_BYTES = 5 * 1024 * 1024
ERROR_LOG_KEEP_BYTES = 1024 * 1024


def systemd_unit(unit: str) -> Optional[NodeService]:
    """The systemd unit *unit* (e.g. found from the node process's cgroup) as a NodeService; None
    on a system without systemd."""
    return os_platform.service_for_unit(unit)


def registered(cfg: BlackboxConfig, home: Optional[Path] = None) -> Optional[NodeService]:
    """The service registered to run this install's node (LaunchAgent / systemd unit), or None.

    None means no service is registered for THIS install's ``dkg_bin`` (not installed, another
    install's, a unit not enabled): the caller runs the node itself. A LaunchAgent registered but
    not loaded IS this install's service — restarting it loads it (KI-529).
    """
    return os_platform.registered(cfg, home if home is not None else Path.home())


def trim_error_log(dkg_home: Path, max_bytes: int = ERROR_LOG_MAX_BYTES, keep_bytes: int = ERROR_LOG_KEEP_BYTES) -> bool:
    """Cut the LaunchAgent error log to its newest *keep_bytes* once it passes *max_bytes*.

    Trims IN PLACE (read the tail, rewrite from the start, truncate) so launchd's open append
    handle keeps writing into the same file. Returns whether it trimmed. Best effort: an
    unreadable or missing log is left alone and logged at DEBUG — the log is diagnostics only.
    """
    path = dkg_home / LAUNCHD_ERROR_LOG
    try:
        if path.stat().st_size <= max_bytes:
            return False
        with path.open("r+b") as log:
            log.seek(-keep_bytes, os.SEEK_END)
            tail = log.read()
            tail = tail[tail.find(b"\n") + 1:]   # start at a whole line
            log.seek(0)
            log.write(tail)
            log.truncate()
        return True
    except OSError as exc:
        logger.debug("blackbox: could not trim %s: %s", path, exc)
        return False


__all__ = [
    "DASHBOARD_LAUNCHD_LABEL",
    "DASHBOARD_SYSTEMD_UNIT",
    "ERROR_LOG_KEEP_BYTES",
    "ERROR_LOG_MAX_BYTES",
    "LAUNCHD_ERROR_LOG",
    "LAUNCHD_LABEL",
    "LAUNCHD_LABELS",
    "SYSTEMD_UNIT",
    "SYSTEMD_UNITS",
    "SYSTEM_UNIT_DIR",
    "WINDOWS_TASKS",
    "NodeService",
    "registered",
    "systemd_unit",
    "trim_error_log",
]
