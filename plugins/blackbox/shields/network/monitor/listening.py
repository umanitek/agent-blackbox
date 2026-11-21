"""Which processes wait for incoming connections, and on which addresses.

``lsof -nP -iTCP -sTCP:LISTEN -F pcn`` prints machine-readable fields, one per line: ``p<pid>``
starts a process, ``c<command>`` names it, ``n<address>:<port>`` is one listening socket
(``*:7000`` = every interface, ``127.0.0.1:9700`` = this machine only). Unprivileged, so it sees
the signed-in user's processes; a socket it cannot see is simply not listed.

Usage::

    found = read()       # {pid: [Listener(address="*", port=7000), ...]}
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from ...json_records import JsonValue, _record_json

LSOF = "/usr/sbin/lsof"
ARGS = ("-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn")
TIMEOUT_SECONDS = 5.0
MAX_PER_PROCESS = 32
_EVERY_INTERFACE = frozenset({"*", "0.0.0.0", "[::]", "::"})


@dataclass(frozen=True)
class Listener:
    """One listening socket: *address* (``*`` for every interface) and *port*."""

    address: str
    port: int

    @property
    def open_to_network(self) -> bool:
        """True when other machines can connect (every interface, or a non-loopback address)."""
        return self.address in _EVERY_INTERFACE or not (self.address.startswith("127.") or self.address in {"[::1]", "::1", "localhost"})

    def as_json(self) -> dict[str, JsonValue]:
        return {**_record_json(self), "open_to_network": self.open_to_network}


def read() -> dict[int, list[Listener]]:
    """Runs ``lsof`` once; empty when it cannot run."""
    try:
        done = subprocess.run([LSOF, *ARGS], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse(done.stdout)   # lsof exits 1 when nothing matched: the text is still right


def parse(text: str) -> dict[int, list[Listener]]:
    """The listeners in ``-F pcn`` output, per pid, without duplicates."""
    found: dict[int, list[Listener]] = {}
    pid = 0
    for line in text.splitlines():
        kind, value = line[:1], line[1:]
        if kind == "p":
            pid = int(value) if value.isdigit() else 0
        elif kind == "n" and pid:
            address, _, port = value.rpartition(":")
            if not port.isdigit() or not address:
                continue
            listener = Listener(address=address, port=int(port))
            listeners = found.setdefault(pid, [])
            if listener not in listeners and len(listeners) < MAX_PER_PROCESS:
                listeners.append(listener)
    return found
