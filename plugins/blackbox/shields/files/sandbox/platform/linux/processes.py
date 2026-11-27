"""What a process is, and stopping one, for the ``stop-processes`` broker (outside the sandbox), read
from ``/proc``. Stopping goes through a pidfd (``pidfd_open`` + ``pidfd_send_signal``): once the
descriptor is open the signal reaches THAT process, never a later one that got its number.

Usage::

    describe(8240)      # ProcessFacts(uid=1000, path="/usr/bin/node", args="node server.js")
    terminate(8240)     # True when the signal was sent
"""

from __future__ import annotations

import os
import signal
from dataclasses import dataclass
from typing import Optional

PROC = "/proc"
#: How a sentence names this operating system ("it is part of Linux").
SYSTEM_NAME = "Linux"
#: Where the system's own programs live: never stopped for an agent (with process 1, which the
#: broker refuses by number).
SYSTEM_PREFIXES = ("/usr/lib/systemd/", "/lib/systemd/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/usr/lib/xorg/",
                   "/usr/bin/gnome-shell", "/usr/bin/plasmashell", "/usr/bin/Xwayland", "/usr/bin/dbus-")
MAX_READ = 64 * 1024


@dataclass(frozen=True)
class ProcessFacts:
    """One process: its owner's ``uid``, its program ``path``, its command line ``args`` and when
    it ``started`` (``/proc/<pid>/stat`` field 22, clock ticks since boot; "" when unknown) — with
    *path*, what tells a process from a later one that got the same number."""

    uid: int
    path: str
    args: str
    started: str = ""


def _read(pid: int, name: str, proc: str) -> bytes:
    with open(os.path.join(proc, str(pid), name), "rb") as handle:   # windows-footgun: ok (Linux module)
        return handle.read(MAX_READ)


def describe(pid: int, proc: str = PROC) -> Optional[ProcessFacts]:
    """The facts of *pid*, or None when it is not running (or can not be read). *proc*: for tests."""
    try:
        status = _read(pid, "status", proc).decode("utf-8", "replace")
        argv = [part.decode("utf-8", "replace") for part in _read(pid, "cmdline", proc).split(b"\0") if part]
    except OSError:
        return None
    uid = next((line.split()[1] for line in status.splitlines() if line.startswith("Uid:") and len(line.split()) > 1), "")
    if not uid.isdigit():
        return None
    try:
        path = os.readlink(os.path.join(proc, str(pid), "exe")).removesuffix(" (deleted)")
    except OSError:
        path = argv[0] if argv else ""
    return ProcessFacts(int(uid), path, " ".join(argv), _started(pid, proc))


def _started(pid: int, proc: str) -> str:
    """Field 22 of ``stat`` (after the command name's closing parenthesis, which may hold spaces)."""
    try:
        fields = _read(pid, "stat", proc).decode("ascii", "replace").rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return ""
    return fields[19] if len(fields) > 19 else ""


def is_system(path: str) -> bool:
    return path.startswith(SYSTEM_PREFIXES)


def terminate(pid: int) -> bool:
    """Asks *pid* to stop (SIGTERM) through a pidfd; True when the signal was sent."""
    try:
        handle = os.pidfd_open(pid)
    except (OSError, AttributeError):
        return False
    try:
        signal.pidfd_send_signal(handle, signal.SIGTERM)
    except OSError:
        return False
    finally:
        os.close(handle)
    return True


__all__ = ["SYSTEM_PREFIXES", "ProcessFacts", "describe", "is_system", "terminate"]
