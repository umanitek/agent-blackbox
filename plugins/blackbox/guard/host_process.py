"""What the Hermes agent's audit trail says about the process a session runs in (KI-572).

The coding agents' hooks name their project folder, process and launch; the Hermes agent's own
hooks recorded only its session id, so its instances showed the Hermes home as the project
(``.hermes``), pid 0 and launch "unknown" (real runs on the test VM, 2026-11-22). The guard runs
INSIDE the Hermes process, so it can say all three exactly:

* ``cwd`` — the folder the agent works in: Hermes's own ``TERMINAL_CWD`` (what its terminal tool
  and ``/checkpoints`` use), else the process's working folder;
* ``pid`` — this process;
* ``launch`` — ``headless`` for a one-shot query (``-q`` / ``--query`` / ``--query-file``),
  ``background`` for a session on a messaging platform or the gateway, else ``interactive``.

Usage::

    facts(platform="cli")   # {"cwd": "/Users/me/app", "pid": 4242, "launch": "headless"}
"""

from __future__ import annotations

import os
import sys
from typing import Any, Optional, Sequence

#: The command-line options that make a Hermes run a single query with no terminal UI.
HEADLESS_OPTIONS = ("-q", "--query", "--query-file")
#: Platforms that are the person at a terminal; any other (telegram, slack, api…) runs in the background.
TERMINAL_PLATFORMS = ("", "cli", "tui", "desktop")


def launch(argv: Sequence[str], platform: str) -> str:
    """How this Hermes session was started (see the module doc)."""
    words = [str(word) for word in argv[1:40]]
    if any(word in HEADLESS_OPTIONS or word.startswith(("--query=", "--query-file=")) for word in words):
        return "headless"
    if "gateway" in words or (platform or "").lower() not in TERMINAL_PLATFORMS:
        return "background"
    return "interactive"


def facts(platform: str = "", argv: Optional[Sequence[str]] = None) -> dict[str, Any]:
    """The project folder, process and launch of the session starting in this process."""
    return {"cwd": (os.environ.get("TERMINAL_CWD") or os.getcwd())[:500], "pid": os.getpid(),
            "launch": launch(sys.argv if argv is None else argv, platform)}


__all__ = ["HEADLESS_OPTIONS", "facts", "launch"]
