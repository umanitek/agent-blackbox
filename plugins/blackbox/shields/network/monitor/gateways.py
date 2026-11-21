"""This machine's default gateways — the router every connection from outside the network comes
through — read-only, unprivileged, re-read at most once a minute.

Why it matters: behind NAT (a home router's port forward, a VM's host, a hotspot) every remote
login attempt arrives FROM the gateway's address. Auto-blocking that address after a burst of
failed logins would refuse every remote connection at once, the person's own included (E2E S4).
:mod:`..protect.remote_lock` asks :func:`addresses` and never auto-blocks one.

macOS: the routing table, ``/usr/sbin/netstat -rn`` (read-only; ``route`` could change routes, so
see-only code never names it), each ``default`` row's gateway. Elsewhere, or when the command
fails: no gateways (the check then blocks as before).

Usage::

    addresses()      # frozenset({"192.168.1.1"})
"""

from __future__ import annotations

import ipaddress
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

NETSTAT = "/usr/sbin/netstat"
#: Seconds the answer is reused (gateways change with the network, not per login attempt).
TTL_SECONDS = 60.0
TIMEOUT_SECONDS = 2.0


@dataclass
class _Cache:
    at: float = -TTL_SECONDS
    found: frozenset[str] = frozenset()


_cache = _Cache()
_lock = threading.Lock()


def parse(table: str) -> frozenset[str]:
    """The gateway of every ``default`` row of a ``netstat -rn`` table (``fe80::1%en0`` → ``fe80::1``;
    a row whose gateway is an interface, ``link#14``, names none)."""
    found: set[str] = set()
    for line in table.splitlines():
        words = line.split()
        if len(words) < 2 or words[0] != "default":
            continue
        try:
            found.add(str(ipaddress.ip_address(words[1].split("%", 1)[0])))
        except ValueError:
            continue
    return frozenset(found)


def _read() -> frozenset[str]:
    try:
        answer = subprocess.run([NETSTAT, "-rn"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    return parse(answer.stdout)


def addresses(now: Optional[float] = None) -> frozenset[str]:
    """The default gateways now (cached for :data:`TTL_SECONDS`)."""
    now = time.monotonic() if now is None else now
    with _lock:
        if now - _cache.at >= TTL_SECONDS:
            _cache.at, _cache.found = now, _read()
        return _cache.found
