"""The service manager registered to supervise this install's DKG node, and how to go through it.

The installer registers the node as a boot service: a systemd unit (``blackbox-dkg``, system or
user scope) on Linux, a LaunchAgent (``ai.umanitek.blackbox-dkg``) on macOS. Anything that
restarts the node must go through that service — a node started behind it is one the service
cannot supervise, and on macOS launchd's own copy then fails "Daemon already running" and is
relaunched for ever (KI-414, KI-426).

The service is found by REGISTRATION, not by inspecting a running process: when the node is down
(stopped for a restart, or crashed) there is no process to inspect, and that is exactly when a
caller would otherwise start an unsupervised copy. A registration counts only when its start
command is THIS install's DKG CLI (``cfg.dkg_bin``), so another install's service on the same
machine is never touched.

Strategy pattern: :class:`NodeService` holds one manager's way of answering "which process do you
run?" and "restart it"; :func:`registered` picks the strategy.

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
import plistlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import psutil

from ..kernel.config import BlackboxConfig

logger = logging.getLogger(__name__)

# THE names of the background services the installers register (scripts/blackbox-install.sh|.ps1
# use the same ones). Uninstall removes the services by these names, through ``sync``'s entry.
LAUNCHD_LABEL = "ai.umanitek.blackbox-dkg"   # = BLACKBOX_DKG_LAUNCHD_LABEL in scripts/blackbox-install.sh
SYSTEMD_UNIT = "blackbox-dkg"
SYSTEM_UNIT_DIR = Path("/etc/systemd/system")
DASHBOARD_LAUNCHD_LABEL = "ai.umanitek.blackbox-dashboard"
DASHBOARD_SYSTEMD_UNIT = "blackbox-dashboard"
WINDOWS_TASKS = ("Agent Blackbox dashboard", "Agent Blackbox DKG node")
#: Every service Blackbox registers, per platform, the dashboard first.
LAUNCHD_LABELS = (DASHBOARD_LAUNCHD_LABEL, LAUNCHD_LABEL)
SYSTEMD_UNITS = (f"{DASHBOARD_SYSTEMD_UNIT}.service", f"{SYSTEMD_UNIT}.service")
# launchd keeps no journal, so the installer sends the LaunchAgent node's stderr here (in the node's
# home, = blackbox_dkg_launchd_error_log in the installer). The node writes its warnings there too,
# a few MB a day, so it is trimmed in place: launchd holds it open for appending, and a replaced
# file would leave launchd writing into a deleted one.
LAUNCHD_ERROR_LOG = "launchd-errors.log"
ERROR_LOG_MAX_BYTES = 5 * 1024 * 1024
ERROR_LOG_KEEP_BYTES = 1024 * 1024
_COMMAND_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class NodeService:
    """One registered service for the node.

    ``name``: shown in logs and errors (``blackbox-dkg.service`` / the LaunchAgent label).
    ``pid_argv``: prints the pid of the process the service runs (empty / 0 when not running).
    ``restart_argv``: restarts the node through the service manager.
    """

    name: str
    pid_argv: tuple[str, ...]
    restart_argv: tuple[str, ...]

    def running_pid(self) -> Optional[int]:
        """The pid of the process the service runs now, or None (not running / no answer)."""
        try:
            result = subprocess.run(list(self.pid_argv), stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        return _pid_in(result.stdout)

    def owns(self, pid: Optional[int]) -> bool:
        """Whether *pid* (the node daemon) is the service's process or its child.

        ``dkg start --foreground`` (what every service runs) is the DKG CLI's supervisor; the node
        daemon is its child and writes its own pid to daemon.pid.
        """
        service_pid = self.running_pid()
        if pid is None or service_pid is None:
            return False
        if pid == service_pid:
            return True
        try:
            return psutil.Process(pid).ppid() == service_pid
        except psutil.Error:
            return False

    def restart(self) -> subprocess.CompletedProcess[str]:
        """Restart the node through the service manager (raises OSError / SubprocessError)."""
        return subprocess.run(list(self.restart_argv), stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=_COMMAND_TIMEOUT_SECONDS, check=False)


def _pid_in(text: str) -> Optional[int]:
    """The pid in ``systemctl show -p MainPID --value`` or ``launchctl print`` output, else None."""
    for line in text.splitlines():
        line = line.strip().removeprefix("pid = ")
        if line.isdigit() and int(line) > 0:
            return int(line)
    return None


def _same_file(a: str, b: str) -> bool:
    try:
        return Path(a).expanduser().resolve() == Path(b).expanduser().resolve()
    except (OSError, RuntimeError):
        return False


def _gui_domain() -> str:
    """launchd's per-user domain, ``gui/<uid>``. Every system with launchd has ``os.getuid``; the
    fallback only keeps this module importable (and its launchd branch testable) on Windows."""
    getuid = getattr(os, "getuid", None)
    return f"gui/{getuid() if getuid is not None else 0}"


def _launch_agent(cfg: BlackboxConfig, home: Path) -> Optional[NodeService]:
    plist_path = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    try:
        program = plistlib.loads(plist_path.read_bytes()).get("ProgramArguments") or []
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if not program or not _same_file(str(program[0]), cfg.dkg_bin):
        return None
    target = f"{_gui_domain()}/{LAUNCHD_LABEL}"
    try:
        loaded = subprocess.run(["launchctl", "print", target], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None
    if not loaded:
        return None   # registered for the next login only: nothing to route through yet
    return NodeService(LAUNCHD_LABEL, ("launchctl", "print", target), ("launchctl", "kickstart", "-k", target))


def _systemd_unit(cfg: BlackboxConfig, home: Path) -> Optional[NodeService]:
    for scope, unit_dir in (((), SYSTEM_UNIT_DIR), (("--user",), home / ".config" / "systemd" / "user")):
        try:
            text = (unit_dir / f"{SYSTEMD_UNIT}.service").read_text(encoding="utf-8-sig")
        except OSError:
            continue
        exec_start = next((line.split("=", 1)[1].split()[0] for line in text.splitlines()
                           if line.startswith("ExecStart=") and line.split("=", 1)[1].split()), "")
        if not exec_start or not _same_file(exec_start, cfg.dkg_bin):
            continue
        systemctl = ("systemctl", *scope)
        try:
            enabled = subprocess.run([*systemctl, "is-enabled", "--quiet", SYSTEMD_UNIT], stdin=subprocess.DEVNULL,
                                     capture_output=True, timeout=10, check=False).returncode == 0
        except (OSError, subprocess.SubprocessError):
            continue
        if enabled:
            return NodeService(f"{SYSTEMD_UNIT}.service", (*systemctl, "show", "-p", "MainPID", "--value", SYSTEMD_UNIT),
                               (*systemctl, "restart", SYSTEMD_UNIT))
    return None


def systemd_unit(unit: str) -> NodeService:
    """The systemd unit *unit* (e.g. found from the node process's cgroup) as a NodeService."""
    return NodeService(unit, ("systemctl", "show", "-p", "MainPID", "--value", unit), ("systemctl", "restart", unit))


def registered(cfg: BlackboxConfig, home: Optional[Path] = None) -> Optional[NodeService]:
    """The service registered to run this install's node (LaunchAgent / systemd unit), or None.

    None means no service runs THIS install's ``dkg_bin`` (not installed, another install's, a
    LaunchAgent not loaded yet, a unit not enabled): the caller runs the node itself.
    """
    home = home if home is not None else Path.home()
    if sys.platform == "darwin":
        return _launch_agent(cfg, home)
    if sys.platform.startswith("linux"):
        return _systemd_unit(cfg, home)
    return None


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

