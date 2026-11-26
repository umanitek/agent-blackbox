"""What a process is, and stopping one, for the ``stop-processes`` broker (outside the sandbox).

Usage::

    describe(8240)      # ProcessFacts(uid=501, path="/opt/homebrew/bin/node", args="node server.js")
    terminate(8240)     # True when the signal was sent
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from typing import Optional

PS = "/bin/ps"
TIMEOUT_SECONDS = 5
#: How a sentence names this operating system ("it is part of macOS").
SYSTEM_NAME = "macOS"
#: Where macOS's own programs live: never stopped for an agent.
SYSTEM_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/Library/Apple/", "/Library/Application Support/Apple/")


@dataclass(frozen=True)
class ProcessFacts:
    """One process: its owner's ``uid``, its program ``path`` and its command line ``args``."""

    uid: int
    path: str
    args: str


def _ps(words: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([PS, *words], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS, check=False)


def describe(pid: int) -> Optional[ProcessFacts]:
    """The facts of *pid*, or None when it is not running (or can not be read)."""
    try:
        done = _ps(["-o", "uid=", "-o", "comm=", "-p", str(pid)])
        args = _ps(["-o", "args=", "-p", str(pid)]).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    head = done.stdout.strip().split(None, 1)
    if done.returncode != 0 or len(head) != 2 or not head[0].isdigit():
        return None
    return ProcessFacts(int(head[0]), head[1], args)


def is_system(path: str) -> bool:
    return path.startswith(SYSTEM_PREFIXES)


def terminate(pid: int) -> bool:
    """Asks *pid* to stop (SIGTERM); True when the signal was sent."""
    try:
        os.kill(pid, signal.SIGTERM)   # windows-footgun: ok (macOS module)
    except OSError:
        return False
    return True


__all__ = ["SYSTEM_NAME", "SYSTEM_PREFIXES", "ProcessFacts", "describe", "is_system", "terminate"]
