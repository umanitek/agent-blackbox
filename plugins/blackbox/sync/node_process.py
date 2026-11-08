"""Which running process is this installation's managed DKG node.

``<dkg_home>/daemon.pid`` is a hint, not the truth. A DKG CLI call made while
the node is already running can auto-spawn a second daemon, which dies on the
busy port and leaves ITS pid in daemon.pid (KI-312; KI-045 is the same
auto-spawn). Anything that acts on the node — the settings check, the
systemd check, restarts, the Node runtime lookup — asks this module instead
of reading the file, so a dead pid never sends a restart behind systemd's
back (the KI-059 shape, seen as KI-306 "did not finish stopping").

Usage::

    pid = managed_daemon_pid(cfg)          # None when no node of ours is running
    for process in managed_daemons(cfg):   # every live daemon process of ours
        ...
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator, List, Optional

import psutil

from ..kernel.config import BlackboxConfig

#: The process roles a DKG node runs as (dkg dist/cli.js): a detached daemon is a
#: supervisor plus a worker; `dkg start --foreground` (the systemd unit) runs a
#: foreground worker. The worker is the one that serves the API.
DAEMON_ROLES = ("daemon-foreground-worker", "daemon-worker", "daemon-supervisor")


def _recorded_pid(cfg: BlackboxConfig) -> Optional[int]:
    try:
        return int((Path(cfg.dkg_home) / "daemon.pid").read_text(encoding="utf-8-sig").strip())
    except (OSError, TypeError, ValueError):
        return None


def _role(cfg: BlackboxConfig, command: list[str]) -> Optional[str]:
    """The daemon role in *command* if it runs THIS installation's DKG CLI, else None."""
    dkg_cli = str(Path(cfg.dkg_bin).expanduser().resolve())
    if dkg_cli not in command:
        return None
    return next((role for role in DAEMON_ROLES if role in command), None)


def managed_daemons(cfg: BlackboxConfig) -> Iterator[psutil.Process]:
    """Every live daemon process of this installation, workers before supervisors.

    Matches only processes running this exact install's DKG CLI, never another
    DKG node on the machine.
    """
    found = []
    try:
        for process in psutil.process_iter(["cmdline", "exe"]):
            try:
                role = _role(cfg, [str(item) for item in (process.info.get("cmdline") or [])])
            except (TypeError, ValueError):
                continue
            if role is not None:
                found.append((DAEMON_ROLES.index(role), process))
    except (OSError, psutil.Error):
        return iter(())
    return iter(process for _rank, process in sorted(found, key=lambda pair: pair[0]))


def is_managed_daemon(cfg: BlackboxConfig, pid: int) -> bool:
    """Whether *pid* is a live daemon process of this installation."""
    try:
        process = psutil.Process(pid)
        return process.is_running() and _role(cfg, [str(item) for item in process.cmdline()]) is not None
    except (OSError, psutil.Error):
        return False


def managed_daemon_pid(cfg: BlackboxConfig) -> Optional[int]:
    """The node's daemon pid: daemon.pid when it names a live daemon of ours,
    else the live daemon found by scanning (worker first), else None."""
    recorded = _recorded_pid(cfg)
    if recorded is not None and is_managed_daemon(cfg, recorded):
        return recorded
    process = next(managed_daemons(cfg), None)
    return process.pid if process is not None else None


def node_starting(cfg: BlackboxConfig, grace_s: float) -> bool:
    """Whether a node of ours is running but started less than *grace_s* seconds ago: it may not
    answer yet (reopening its store takes about a minute after a boot), so it is starting, not down."""
    pid = managed_daemon_pid(cfg)
    if pid is None:
        return False
    try:
        return time.time() - psutil.Process(pid).create_time() < grace_s
    except (OSError, psutil.Error):
        return False

