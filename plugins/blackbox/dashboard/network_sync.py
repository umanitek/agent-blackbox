"""The command line the dashboard runs for its verified-graph sync.

The dashboard runs ``blackbox sync`` in a child process so a long network
transfer stays isolated from the web server (see ``server._network_sync_once``), and at a lower
CPU and disk priority than the dashboard that answers the agents' hooks.

Usage: pass ``network_sync_argv(3600)`` as the argv of the child process
(the caller sets stdin, capture and timeout).
"""

from __future__ import annotations

import shutil

from ..kernel.host_command import hermes_argv

#: How far the sync child steps back (``nice``): it yields the CPU to the person's own work and to
#: the dashboard, which answers the agents' hooks. WHY (Linux round L7, BB-LINUX-PENDING-88f30f):
#: the first graph sync held cores for 1-3 hours at normal priority. Only under contention — an idle
#: machine syncs at full speed — and no poll's pace changes: the sync starts when it did.
SYNC_NICENESS = 10


def _lowered(argv: list[str]) -> list[str]:
    """*argv* run at :data:`SYNC_NICENESS`, and at the lowest best-effort disk priority where ``ionice`` exists
    (Linux); unchanged where neither program is found (Windows)."""
    nice, ionice = shutil.which("nice"), shutil.which("ionice")
    prefix = ([ionice, "-c", "2", "-n", "7"] if ionice else []) + ([nice, "-n", str(SYNC_NICENESS)] if nice else [])
    return prefix + argv


def network_sync_argv(timeout: int = 3600) -> list[str]:
    """Run the canonical verified graph sync in an isolated, lowered-priority process."""
    return _lowered(hermes_argv("blackbox", "sync", "--wait", "--timeout", str(max(1, int(timeout))), "--require-rules"))
