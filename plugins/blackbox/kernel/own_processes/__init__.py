"""Blackbox's own running programs — the ones self-protection refuses an agent's signal to.

Private security finding ``2026-11-24-linux-an-agent-stops-blackbox-s-dashboar`` (Linux round L1,
High): REAL Claude Code ran ``kill <the dashboard's pid>``; the hook allowed it (the number names
nothing), systemd left the unit down (``Restart=on-failure``: a SIGTERM is a clean exit) and the
hooks failed open. ``pkill python3``, ``killall -9 …``, ``kill -9 -1`` passed the same way. A kill
names Blackbox only through the machine: which pid, process group, name or command line is ours.

:func:`running` answers that: every process whose command line runs Blackbox (``… blackbox
dashboard`` and the other ``blackbox`` commands of a Hermes, the system protection helper
``blackbox-netd``, Blackbox's notifier and sandbox launcher) and Blackbox's own DKG node (the pid
its ``daemon.pid`` names, when that process is a ``dkg`` one). Read through psutil, kept for
:data:`KEEP_SECONDS` (one lock), asked only when a command could signal something.

Usage::

    from plugins.blackbox.kernel import own_processes
    [process.pid for process in own_processes.running()]
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from .. import constants
from ..bounded_files import read_small_text

__all__ = ["KEEP_SECONDS", "OwnProcess", "is_own", "running"]

#: How long one reading of the process table is kept.
KEEP_SECONDS = 2.0
#: The program names of Blackbox's own binaries.
_OWN_PROGRAMS = frozenset({"blackbox-netd", "blackbox-sandbox", "blackbox-notifier", "Blackbox Notifier"})


@dataclass(frozen=True)
class OwnProcess:
    """One of Blackbox's processes: its pid, its process group, its program name (what ``pkill``
    and ``killall`` match without ``-f``) and its whole command line (what ``pkill -f`` matches)."""

    pid: int
    group: int
    name: str
    command: str


def is_own(argv: list[str]) -> bool:
    """True when command line *argv* runs Blackbox: a ``blackbox`` subcommand of a Hermes (``hermes
    blackbox dashboard``, ``python -m hermes_cli.main blackbox curate``) or one of Blackbox's own
    programs."""
    if not argv:
        return False
    if os.path.basename(argv[0]) in _OWN_PROGRAMS:
        return True
    words = [os.path.basename(word) for word in argv[:6]]
    return "blackbox" in words[1:] and any("hermes" in word for word in words[:4])


def _node_pid() -> int:
    text = read_small_text(constants.blackbox_dkg_home() / "daemon.pid", 64) or ""
    return int(text.strip()) if text.strip().isdigit() else 0


def _read() -> tuple[OwnProcess, ...]:
    try:
        import psutil
    except ImportError:   # pragma: no cover - psutil ships with Hermes
        return ()
    node, found = _node_pid(), []
    for process in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            argv = process.info.get("cmdline") or []
            # WHY the name too (KI-700, macOS round R8): the system protection helper runs as root,
            # whose command line the person's processes may not read (psutil answers None), so
            # ``sudo kill -9 <helper pid>`` named nothing ours; its program name stays readable.
            named = process.info.get("name") or ""
            ours = is_own(argv) or named in _OWN_PROGRAMS or (process.info["pid"] == node and any("dkg" in word for word in argv[:4]))
            if ours:
                found.append(OwnProcess(process.info["pid"], os.getpgid(process.info["pid"]), named, " ".join(argv)[:2000] or named))
        except (psutil.Error, OSError):   # gone, or another user's: not something to protect here
            continue
    return tuple(found)


_lock = threading.Lock()
_kept: tuple[float, tuple[OwnProcess, ...]] = (0.0, ())


def running() -> tuple[OwnProcess, ...]:
    """Blackbox's processes now (kept :data:`KEEP_SECONDS`)."""
    global _kept
    with _lock:
        if time.monotonic() >= _kept[0]:
            _kept = (time.monotonic() + KEEP_SECONDS, _read())
        return _kept[1]
