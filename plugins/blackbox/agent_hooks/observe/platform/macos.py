"""macOS: the process list and one process's environment, as ``ps`` prints them (read-only)."""

from __future__ import annotations

import subprocess

TIMEOUT_SECONDS = 4.0
MAX_OUTPUT_CHARS = 4 * 1024 * 1024


def _run(argv: list[str]) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout[:MAX_OUTPUT_CHARS] if done.returncode == 0 else ""


def process_table() -> str:
    """Every process as ``pid ppid <lstart: 5 words> command…``, one per line."""
    return _run(["/bin/ps", "-axo", "pid=,ppid=,lstart=,command="])


def process_environment(pid: int) -> str:
    """*pid*'s command line followed by its environment (``NAME=value`` words) — only for this
    user's own processes, and empty for the programs macOS keeps closed."""
    return _run(["/bin/ps", "eww", "-o", "command=", "-p", str(int(pid))])
