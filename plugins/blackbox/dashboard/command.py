"""``blackbox dashboard`` — start the local dashboard (replacing a stale one on the port)."""

from __future__ import annotations

import argparse
import logging
import os
from .. import attach
from ..kernel.config import load_blackbox_config

logger = logging.getLogger(__name__)

def cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    port = args.port or cfg.dashboard_port
    try:
        from .server import start_dashboard
    except Exception as exc:
        print(f"error: dashboard requires the [web] extra (fastapi/uvicorn): {exc}")
        return 1
    if not _replace_existing_dashboard(port):
        return 1
    try:
        report = attach.attach_all(hermes=True, openclaw=True, dry_run=False)
        newly = [r for r in report.get("hermes", []) + report.get("openclaw", []) if not r.get("already") and not r.get("error")]
        if newly:
            for row in report.get("hermes", []):
                if not row.get("already") and not row.get("error"):
                    attach.print_hermes_attach_row(row, "Auto-attached")
            for row in report.get("openclaw", []):
                if not row.get("already") and not row.get("error"):
                    attach.print_openclaw_attach_row(row, "Auto-attached")
            print("  Restart any running agent to activate.")
    except Exception as exc:
        logger.debug("dashboard auto-attach skipped: %s", exc)
    print(f"Starting Blackbox dashboard on http://127.0.0.1:{port} (Ctrl-C to stop)")
    start_dashboard(port)
    return 0


def _replace_existing_dashboard(port: int) -> bool:
    """Make ``port`` ours before binding: a Blackbox dashboard already on it is
    stopped (SIGTERM, then SIGKILL after 3 s) so re-running ``blackbox dashboard``
    restarts it; anything else holding the port is left alone and named, and
    this returns False. Never signals ourselves. Fail-open: any error proceeds
    to the bind, which surfaces the normal port-in-use error.

    Why the ownership check: the port is a shared machine resource, and the
    working rule is never to kill a process you did not start — a reboot script
    once held 9700 with another product's service."""
    pids = _listening_pids(port)
    if not pids:
        return True
    ours = {pid for pid in pids if _is_blackbox_dashboard(pid)}
    strangers = pids - ours
    if strangers:
        named = ", ".join(f"{pid} ({_process_name(pid)})" for pid in sorted(strangers))
        print(f"error: port {port} is held by pid {named}, which is not a Blackbox dashboard — "
              f"Blackbox will not stop it. Start on another port: blackbox dashboard --port {port + 1}")
        return False
    print(f"restarting: found existing dashboard on port {port} (pid {', '.join(str(p) for p in sorted(ours))}) — stopping it...")
    _stop(ours)
    return True


def stop_running_dashboard(port: int) -> list[int]:
    """Stop the Blackbox dashboard serving loopback ``port``, if one does; returns the pids stopped.

    For `blackbox uninstall`: setup starts the dashboard directly (its login service takes over at
    the next login), so removing the service does not stop it, and a dashboard left running
    re-creates $BLACKBOX_HOME. Same ownership rule as a restart: only a process whose own command
    line is ``… blackbox dashboard``; anything else on the port is left alone."""
    ours = sorted(pid for pid in _listening_pids(port) if _is_blackbox_dashboard(pid))
    if ours:
        _stop(set(ours))
    return ours


def _listening_pids(port: int) -> set[int]:
    """Other processes listening on loopback ``port`` (empty when nothing answers or lsof is missing)."""
    import shutil
    import socket
    import subprocess

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        if sock.connect_ex(("127.0.0.1", int(port))) != 0:
            return set()
    finally:
        sock.close()
    lsof = shutil.which("lsof")
    if not lsof:
        print(f"warning: port {port} in use but 'lsof' unavailable — cannot auto-restart.")
        return set()
    try:
        out = subprocess.run([lsof, "-tiTCP:" + str(int(port)), "-sTCP:LISTEN"],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3, check=False).stdout
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        logger.debug("dashboard auto-restart: lsof failed: %s", exc)
        return set()
    return {int(p) for p in out.split() if p.isdigit() and int(p) != os.getpid()}


def _is_blackbox_dashboard(pid: int) -> bool:
    """True only when the process's own command line is ``… blackbox dashboard``
    (how the installer, launchd and systemd all start it). Unknown = not ours."""
    tokens = _cmdline(pid)
    return "blackbox" in tokens and "dashboard" in tokens


def _cmdline(pid: int) -> list[str]:
    try:
        import psutil
    except ImportError:   # pragma: no cover - never a reason to kill
        return []
    try:
        return [os.path.basename(t) if i == 0 else t for i, t in enumerate(psutil.Process(pid).cmdline())]
    except (psutil.Error, OSError):   # gone or denied: unknown is never ours
        return []


def _process_name(pid: int) -> str:
    tokens = _cmdline(pid)
    return " ".join(tokens[:3]) if tokens else "unknown process"


def _stop(pids: set[int]) -> None:
    """SIGTERM each pid, wait up to 3 s, SIGKILL the stragglers. Best-effort."""
    import signal
    import time as _time

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as exc:
            logger.debug("dashboard auto-restart: SIGTERM %s failed: %s", pid, exc)
    try:
        import psutil
    except ImportError:   # pragma: no cover - fail open
        return
    alive: list[int] = []
    for _ in range(30):
        alive = [pid for pid in pids if psutil.pid_exists(pid)]
        if not alive:
            return
        _time.sleep(0.1)
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    for pid in alive:
        try:
            os.kill(pid, kill_signal)
        except OSError as exc:
            logger.debug("dashboard auto-restart: SIGKILL %s failed: %s", pid, exc)
