"""macOS: the node's LaunchAgent (``ai.umanitek.blackbox-dkg``), found by its registration and
reached through ``launchctl`` (see ``sync.node_service`` for why only the service may restart it)."""

from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
from pathlib import Path
from typing import Optional

from ...kernel.bounded_files import read_small_text
from ...kernel.config import BlackboxConfig
from .model import LAUNCHD_LABEL, NodeService, same_file as _same_file

# The installer's service launcher (write_service_launcher): its marker line and its program loop.
_LAUNCHER_MARKER = "started by launchd for Agent Blackbox"
_LAUNCHER_LOOP = "for program in"
_LAUNCHER_MAX_BYTES = 4096


def _gui_domain() -> str:
    """launchd's per-user domain, ``gui/<uid>``. Every system with launchd has ``os.getuid``; the
    fallback only keeps this module importable (and its launchd branch testable) on Windows."""
    getuid = getattr(os, "getuid", None)
    return f"gui/{getuid() if getuid is not None else 0}"


def _launcher_programs(path: str) -> tuple[str, ...]:
    """The programs a Blackbox service launcher may start, in order; () for anything else.

    The installer's LaunchAgents start a small launcher script (``<BLACKBOX_HOME>/bin/Blackbox Node``,
    ``write_service_launcher`` in scripts/blackbox-install.sh, FIX-0255) instead of the program
    itself, so macOS shows "Blackbox" and an update that moves the program never breaks the job.
    Its one ``for program in '<path>' …; do`` line names the candidates (shell single-quoted).
    """
    text = read_small_text(path, _LAUNCHER_MAX_BYTES)
    if text is None or _LAUNCHER_MARKER not in text:
        return ()
    for line in text.splitlines():
        if line.startswith(_LAUNCHER_LOOP) and line.rstrip().endswith("; do"):
            try:
                return tuple(shlex.split(line[len(_LAUNCHER_LOOP):line.rstrip().rindex("; do")]))
            except ValueError:
                return ()
    return ()


def _starts_this_install_s_node(program: str, cfg: BlackboxConfig) -> bool:
    """Whether a service's first argument runs THIS install's DKG CLI: the CLI itself, or a
    Blackbox launcher whose candidates include it. Keyed on the resolved path (LES-105)."""
    if _same_file(program, cfg.dkg_bin):
        return True
    return any(_same_file(candidate, cfg.dkg_bin) for candidate in _launcher_programs(program))


def _launch_agent(cfg: BlackboxConfig, home: Path) -> Optional[NodeService]:
    plist_path = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    try:
        program = plistlib.loads(plist_path.read_bytes()).get("ProgramArguments") or []
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if not program or not _starts_this_install_s_node(str(program[0]), cfg):
        return None
    target = f"{_gui_domain()}/{LAUNCHD_LABEL}"
    try:
        loaded = subprocess.run(["launchctl", "print", target], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None
    if not loaded:
        # Registered but not loaded (booted out by Stop, or the handover's fallback): the node is
        # still launchd's to run, so it is started by loading the agent (RunAtLoad), never by a
        # copy started here that launchd's own copy would then fight (KI-529). A refused
        # bootstrap (no GUI session) raises in the caller instead of starting an unsupervised node.
        return NodeService(LAUNCHD_LABEL, ("launchctl", "print", target),
                           ("launchctl", "bootstrap", _gui_domain(), str(plist_path)))
    return NodeService(LAUNCHD_LABEL, ("launchctl", "print", target), ("launchctl", "kickstart", "-k", target))


def registered(cfg: BlackboxConfig, home: Path) -> Optional[NodeService]:
    """The LaunchAgent registered to run this install's node, or None."""
    return _launch_agent(cfg, home)


def service_for_unit(_unit: str) -> Optional[NodeService]:
    """No systemd here."""
    return None


__all__ = ["registered", "service_for_unit"]
