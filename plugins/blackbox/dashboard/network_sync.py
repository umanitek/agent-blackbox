"""The command line the dashboard runs for its verified-graph sync.

The dashboard runs ``blackbox sync`` in a child process so a long network
transfer stays isolated from the web server (see ``server._network_sync_once``).

Usage: pass ``network_sync_argv(3600)`` as the argv of the child process
(the caller sets stdin, capture and timeout).
"""

from __future__ import annotations

from ..kernel.host_command import hermes_argv


def network_sync_argv(timeout: int = 3600) -> list[str]:
    """Run the canonical verified graph sync in an isolated process."""
    return hermes_argv("blackbox", "sync", "--wait", "--timeout", str(max(1, int(timeout))), "--require-rules")
