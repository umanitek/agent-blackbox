"""macOS: the programs Network Shield's monitor runs to see this Mac. Read-only, unprivileged,
each bounded by a timeout (a stuck program never holds a dashboard request). Each answers the
program's text, or ``None`` / ``""`` when it cannot run — see the facade, ``platform/__init__``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

NETTOP = "/usr/bin/nettop"
NETTOP_ARGS = ("-L", "1", "-x", "-n", "-J", "state,bytes_in,bytes_out")
LSOF = "/usr/sbin/lsof"
LSOF_ARGS = ("-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn")
NETSTAT = "/usr/sbin/netstat"
PS = "/bin/ps"
CODESIGN = "/usr/bin/codesign"
#: Where the Tailscale command lives (the Mac app's, Homebrew's, the standalone install's).
TAILSCALE_COMMANDS = ("/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale")
#: nettop answers in ~15 ms; ps, lsof and codesign in well under a second.
TIMEOUT_SECONDS = 5.0
ROUTES_TIMEOUT_SECONDS = 2.0
TAILSCALE_TIMEOUT_SECONDS = 3.0


def _run(argv: list[str], timeout: float, *, closed_stdin: bool = True) -> Optional[subprocess.CompletedProcess[str]]:
    """Runs *argv* once; None when it cannot run or does not finish in *timeout* seconds."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL if closed_stdin else None, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def traffic_unavailable() -> Optional[str]:
    """None: this Mac's connections can be read."""
    return None


def connection_table() -> Optional[str]:
    """``nettop``'s CSV of every connection with its state and bytes; None when it failed."""
    done = _run([NETTOP, *NETTOP_ARGS], TIMEOUT_SECONDS)
    return done.stdout if done is not None and done.returncode == 0 else None


def listening_table() -> str:
    """``lsof -F pcn`` of every listening TCP socket ("" when it cannot run; lsof exits 1 when
    nothing matched, and the text is still right)."""
    done = _run([LSOF, *LSOF_ARGS], TIMEOUT_SECONDS)
    return done.stdout if done is not None else ""


def routing_table() -> str:
    """``netstat -rn`` ("" when it cannot run). Read-only: ``route`` could change routes."""
    done = _run([NETSTAT, "-rn"], ROUTES_TIMEOUT_SECONDS, closed_stdin=False)
    return done.stdout if done is not None else ""


def process_table() -> Optional[str]:
    """``ps -axo pid=,ppid=,%cpu=,rss=,args=`` (rss in KiB); None when it failed."""
    done = _run([PS, "-axo", "pid=,ppid=,%cpu=,rss=,args="], TIMEOUT_SECONDS)
    return done.stdout if done is not None and done.returncode == 0 else None


def process_paths(timeout: float = TIMEOUT_SECONDS) -> str:
    """``ps -axo pid=,comm=``: every process's executable ("" when it cannot run)."""
    done = _run([PS, "-axo", "pid=,comm="], timeout, closed_stdin=False)
    return done.stdout if done is not None else ""


def code_signature(path: str) -> Optional[str]:
    """What ``codesign -dv --verbose=2 <path>`` displays (it writes to stderr); None when it cannot run."""
    done = _run([CODESIGN, "-dv", "--verbose=2", path], TIMEOUT_SECONDS)
    return done.stderr + done.stdout if done is not None else None


def tailscale_status() -> Optional[str]:
    """``tailscale status --json`` when Tailscale is installed and answers; else None."""
    command = next((path for path in TAILSCALE_COMMANDS if Path(path).exists()), None)
    if command is None:
        return None
    done = _run([command, "status", "--json"], TAILSCALE_TIMEOUT_SECONDS, closed_stdin=False)
    return done.stdout if done is not None and done.returncode == 0 else None
