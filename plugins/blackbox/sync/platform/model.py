"""What every ``sync/platform/<os>`` module shares: the names of the services the installers
register (THE names — scripts/blackbox-install.sh|.ps1 use the same ones; uninstall removes the
services by them, through ``sync``'s entry) and :class:`NodeService`, one manager's way of answering
"which process do you run?" and "restart it" (a Strategy record each OS module builds)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import psutil

LAUNCHD_LABEL = "ai.umanitek.blackbox-dkg"   # = BLACKBOX_DKG_LAUNCHD_LABEL in scripts/blackbox-install.sh
SYSTEMD_UNIT = "blackbox-dkg"
SYSTEM_UNIT_DIR = Path("/etc/systemd/system")
DASHBOARD_LAUNCHD_LABEL = "ai.umanitek.blackbox-dashboard"
DASHBOARD_SYSTEMD_UNIT = "blackbox-dashboard"
WINDOWS_TASKS = ("Agent Blackbox dashboard", "Agent Blackbox DKG node")
#: Every service Blackbox registers, per platform, the dashboard first.
LAUNCHD_LABELS = (DASHBOARD_LAUNCHD_LABEL, LAUNCHD_LABEL)
SYSTEMD_UNITS = (f"{DASHBOARD_SYSTEMD_UNIT}.service", f"{SYSTEMD_UNIT}.service")
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
        # WHY ancestry, not only the parent (KI-541): under launchd the service runs Blackbox's
        # "Blackbox Node" launcher, so the daemon can be the service's grandchild
        # (launcher -> `dkg start --foreground` -> daemon); a parent-only check called the
        # service's own node unsupervised and every sync wanted to restart it.
        current: Optional[int] = pid
        for _ in range(_OWNERSHIP_LEVELS):
            if current is None or current <= 1:
                return False
            if current == service_pid:
                return True
            try:
                current = psutil.Process(current).ppid()
            except psutil.Error:
                return False
        return False

    def restart(self) -> subprocess.CompletedProcess[str]:
        """Restart the node through the service manager (raises OSError / SubprocessError)."""
        return subprocess.run(list(self.restart_argv), stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=_COMMAND_TIMEOUT_SECONDS, check=False)


#: How many parents up the service's process may be from the node daemon (launcher, CLI, daemon).
_OWNERSHIP_LEVELS = 6


def _pid_in(text: str) -> Optional[int]:
    """The pid in ``systemctl show -p MainPID --value`` or ``launchctl print`` output, else None."""
    for line in text.splitlines():
        line = line.strip().removeprefix("pid = ")
        if line.isdigit() and int(line) > 0:
            return int(line)
    return None


def same_file(a: str, b: str) -> bool:
    """Whether *a* and *b* name the same file (resolved: LES-105)."""
    try:
        return Path(a).expanduser().resolve() == Path(b).expanduser().resolve()
    except (OSError, RuntimeError):
        return False


__all__ = [
    "DASHBOARD_LAUNCHD_LABEL",
    "DASHBOARD_SYSTEMD_UNIT",
    "LAUNCHD_LABEL",
    "LAUNCHD_LABELS",
    "SYSTEMD_UNIT",
    "SYSTEMD_UNITS",
    "SYSTEM_UNIT_DIR",
    "WINDOWS_TASKS",
    "NodeService",
    "same_file",
]
