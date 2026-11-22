"""Remote-control apps and tunnels on this machine — the ways in that do NOT arrive on a port.

Remote-control apps (TeamViewer, AnyDesk, Chrome Remote Desktop, RustDesk …) connect OUT to their
vendor's relay and take control through it, so watching inbound ports misses them; tunnels
(ngrok, cloudflared, frp, chisel …) open this machine to the internet from the inside. Both are
recognised by the program itself, from :file:`catalog.json` (Blackbox's own list): by executable
name or app folder. One is **active** while it holds a network connection (or listens). An SSH
client that listens on a local port is a forwarding tunnel (``ssh -L`` / ``-D``); a remote
forward (``ssh -R``) leaves no local trace and is not seen here.

Read-only: ``ps`` (executables only, never arguments), the plugin's network monitor and the
listening-socket reader. Usage::

    found = detect(processes)          # pure: [(pid, path, connected, listening ports)] → apps, tunnels
    found = read()                     # this machine, cached CATALOG_TTL seconds
    relay_domains()                    # every catalogued app's relay domains (for Lock remote access)
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .....shields.network import monitor
from .. import listening, platform

#: How long one machine-wide look is reused (the page asks every second; nettop costs ~0.3 s).
CATALOG_TTL = 5.0
PS_TIMEOUT = 5.0
_CATALOG = json.loads((Path(__file__).with_name("catalog.json")).read_text(encoding="utf-8-sig"))


@dataclass(frozen=True)
class Running:
    """One process as detection needs it."""

    pid: int
    path: str
    connected: bool = False
    listening: tuple[int, ...] = ()


#: macOS's own read-only system folders (System Integrity Protection): nothing there is a
#: third-party remote-control app. WHY: matching by executable name alone took Apple's Spotlight
#: helper /System/Library/PrivateFrameworks/CoreParsec.framework/parsecd for Parsec (E2E 2026-11-21).
_SYSTEM_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/")


def _matches(entry: dict[str, Any], path: str) -> bool:
    if path.startswith(_SYSTEM_PREFIXES):
        return False
    name = path.rsplit("/", 1)[-1].lower()
    return name in entry.get("executables", ()) or any(f"/{app}/" in path for app in entry.get("apps", ()))


def detect(processes: Iterable[Running]) -> dict[str, list[dict[str, Any]]]:
    """The catalogued apps and tunnels among *processes*: each with its pids, active or not;
    plus SSH clients listening on a local port (forwarding tunnels)."""
    processes = list(processes)
    apps, tunnels = [], []
    for kind, entries, out in (("app", _CATALOG["apps"], apps), ("tunnel", _CATALOG["tunnels"], tunnels)):
        for entry in entries:
            found = [p for p in processes if _matches(entry, p.path)]
            if found:
                out.append({"id": entry["id"], "name": entry["name"], "kind": kind, "pids": sorted(p.pid for p in found),
                            "active": any(p.connected or p.listening for p in found)})
    for process in processes:
        if process.path.rsplit("/", 1)[-1] == "ssh" and process.listening:
            tunnels.append({"id": f"ssh-forward-{process.pid}", "name": "SSH port forwarding", "kind": "tunnel",
                            "pids": [process.pid], "active": True, "ports": sorted(process.listening)[:10]})
    return {"apps": apps, "tunnels": tunnels}


def relay_domains() -> list[str]:
    """Every catalogued remote-control app's relay domains (refused while Lock remote access is on)."""
    return sorted({domain for entry in _CATALOG["apps"] for domain in entry.get("relay_domains", ())})


def _executables() -> dict[int, str]:
    text = platform.process_paths(PS_TIMEOUT)
    out = {}
    for line in text.splitlines():
        pid, _, path = line.strip().partition(" ")
        if pid.isdigit():
            out[int(pid)] = path.strip()
    return out


_cache: dict[str, Any] = {"at": 0.0, "found": {"apps": [], "tunnels": []}}
_lock = threading.Lock()


def read() -> dict[str, list[dict[str, Any]]]:
    """This machine's remote-control apps and tunnels, re-read at most every CATALOG_TTL seconds."""
    with _lock:
        if time.time() - _cache["at"] < CATALOG_TTL:
            return _cache["found"]
    paths = _executables()
    reading = monitor.read()
    connected = {p.pid for p in reading.processes if any(not c.local for c in p.connections)}
    listeners = listening.read()
    found = detect(Running(pid, path, pid in connected, tuple(sorted({l.port for l in listeners.get(pid, [])})))
                   for pid, path in paths.items())
    with _lock:
        _cache.update(at=time.time(), found=found)
    return found
