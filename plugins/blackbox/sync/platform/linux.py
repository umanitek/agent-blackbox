"""Linux: the node's systemd unit (``blackbox-dkg``, system or user scope), found by its
registration and reached through ``systemctl``."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from ...kernel.config import BlackboxConfig
from .model import SYSTEM_UNIT_DIR, SYSTEMD_UNIT, NodeService, same_file as _same_file


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


def service_for_unit(unit: str) -> NodeService:
    """The systemd unit *unit* (e.g. found from the node process's cgroup) as a NodeService."""
    return NodeService(unit, ("systemctl", "show", "-p", "MainPID", "--value", unit), ("systemctl", "restart", unit))


#: The name managed_node knew it by (a unit found from the node process's cgroup).
systemd_unit = service_for_unit


def registered(cfg: BlackboxConfig, home: Path) -> Optional[NodeService]:
    """The enabled systemd unit registered to run this install's node, or None."""
    return _systemd_unit(cfg, home)


__all__ = ["registered", "service_for_unit", "systemd_unit"]
