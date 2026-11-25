"""Names for the addresses people come in from: the Tailscale machine name of a tailnet address
("Main Mac" rather than 100.101.102.103), and the host name a reverse lookup gives.

Both are read-only and never make a page wait: Tailscale's own status is read only when the
Tailscale command is installed (``tailscale status --json``, cached :data:`TAILSCALE_TTL`
seconds); reverse lookups run on one background thread and answer from a bounded cache — the
first ask answers "" and the name appears on a later one.
"""

from __future__ import annotations

import json
import queue
import socket
import threading
import time
from typing import Any

from .. import platform

TAILSCALE_TTL = 60.0
MAX_NAMES = 2000

_tailscale: dict[str, Any] = {"at": 0.0, "names": {}}
_hosts: dict[str, str] = {}
_asked: set[str] = set()
_wanted: queue.Queue[str] = queue.Queue(maxsize=200)
_lock = threading.Lock()
_worker: list[threading.Thread] = []


def parse_tailscale(text: str) -> dict[str, str]:
    """address → machine name, from ``tailscale status --json`` (this machine and every peer)."""
    try:
        status = json.loads(text)
    except ValueError:
        return {}
    names: dict[str, str] = {}
    nodes = [status.get("Self") or {}] + list((status.get("Peer") or {}).values())
    for node in nodes:
        name = str(node.get("HostName") or node.get("DNSName") or "").split(".")[0][:64]
        for address in node.get("TailscaleIPs") or ():
            if name:
                names[str(address)] = name
    return names


def tailscale_name(address: str) -> str:
    """The tailnet machine behind *address* ("" when not a tailnet peer or Tailscale is absent)."""
    with _lock:
        fresh = time.time() - _tailscale["at"] < TAILSCALE_TTL
        if fresh:
            return _tailscale["names"].get(address, "")
    text = platform.tailscale_status()
    names = parse_tailscale(text) if text is not None else {}
    with _lock:
        _tailscale.update(at=time.time(), names=names)
    return names.get(address, "")


def _resolve_forever() -> None:
    while True:
        address = _wanted.get()
        try:
            name = socket.gethostbyaddr(address)[0][:128]
        except (OSError, UnicodeError):
            name = ""
        with _lock:
            if len(_hosts) >= MAX_NAMES:
                _hosts.clear()
                _asked.clear()
            _hosts[address] = name


def host_name(address: str) -> str:
    """The reverse-lookup name of *address* if known; asks for it in the background otherwise."""
    with _lock:
        if address in _hosts:
            return _hosts[address]
        if address in _asked:
            return ""
        _asked.add(address)
        if not _worker:
            thread = threading.Thread(target=_resolve_forever, name="blackbox-remote-names", daemon=True)
            thread.start()
            _worker.append(thread)
    try:
        _wanted.put_nowait(address)
    except queue.Full:
        pass
    return ""
