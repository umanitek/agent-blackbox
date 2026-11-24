"""Linux: the programs Network Shield's monitor runs to see this machine, their answers rendered
into the macOS tools' formats so the monitor's parsers stay one (Linux deep layers step 3).
Read-only, unprivileged, each bounded by a timeout — see the facade, ``platform/__init__``.

* :func:`connection_table` — ``ss -tuanpiH`` rendered as ``nettop``'s CSV (process rows, then
  their socket rows with state and bytes). A UDP socket connected to port 443 is labelled
  ``quic4`` / ``quic6`` (a heuristic: Linux does not name QUIC apart). Bytes come from TCP's
  ``bytes_received`` / ``bytes_sent``; UDP bytes are not measured (0).
* :func:`listening_table` — ``ss -ltnpH`` rendered as ``lsof -F pcn``.
* :func:`routing_table` — the kernel's routing tables (``/proc/net/route``, ``/proc/net/ipv6_route``;
  read, no program run) rendered as ``netstat -rn``'s ``default <gateway>`` rows.
* :func:`process_table` — ``ps -eo`` with the same columns as macOS; :func:`process_paths`
  reads each process's executable from ``/proc`` (no program run).

Limits, unprivileged: ``ss -p`` names the process of this user's own sockets only, so another
user's connections (root's ``sshd``) are not attributed here — the root helper sees them all.
The ``render_*`` functions are pure, so a test feeds them recorded output on any OS.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

#: Where each tool lives across distributions (usrmerge or not, Fedora's sbin).
SS_COMMANDS = ("/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss")
PS_COMMANDS = ("/usr/bin/ps", "/bin/ps")
SS_CONNECTIONS_ARGS = ("-tuanpiH",)
SS_LISTENING_ARGS = ("-ltnpH",)
TAILSCALE_COMMANDS = ("/usr/bin/tailscale", "/usr/local/bin/tailscale", "/usr/sbin/tailscale", "/snap/bin/tailscale")
PROC_ROOT = "/proc"
#: The routing tables' size is bounded by the routes a machine has; more is never needed.
MAX_ROUTES_BYTES = 256 * 1024
#: The kernel's routing tables (read; nothing is run).
ROUTES_V4 = "/proc/net/route"
ROUTES_V6 = "/proc/net/ipv6_route"
#: ``/proc/net/route`` flag: the route goes through a gateway.
RTF_GATEWAY = 0x2
TIMEOUT_SECONDS = 5.0
TAILSCALE_TIMEOUT_SECONDS = 3.0
#: nettop's header for the CSV :func:`render_connections` writes.
NETTOP_HEADER = ",state,bytes_in,bytes_out,"
#: ss's TCP state → nettop's spelling (the Rust reader's ``tcp_state_name`` uses the same).
NETTOP_STATES = {
    "ESTAB": "Established", "LISTEN": "Listen", "SYN-SENT": "SynSent", "SYN-RECV": "SynReceived",
    "FIN-WAIT-1": "FinWait1", "FIN-WAIT-2": "FinWait2", "TIME-WAIT": "TimeWait", "CLOSE-WAIT": "CloseWait",
    "LAST-ACK": "LastAck", "CLOSING": "Closing", "CLOSE": "Closed", "UNCONN": "",
}
QUIC_PORT = 443
_NETIDS = frozenset({"tcp", "udp"})
_USER = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+),fd=\d+\)')
_COUNTER = re.compile(r"\b(bytes_received|bytes_sent|bytes_acked):(\d+)")
_ANY = frozenset({"*", "0.0.0.0", "::"})


def _first(paths: Iterable[str]) -> Optional[str]:
    return next((path for path in paths if Path(path).exists()), None)


def _run(argv: list[str], timeout: float) -> Optional[subprocess.CompletedProcess[str]]:
    """Runs *argv* once; None when it cannot run or does not finish in *timeout* seconds."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _tool_text(commands: Iterable[str], args: Iterable[str], timeout: float) -> Optional[str]:
    command = _first(commands)
    done = _run([command, *args], timeout) if command else None
    return done.stdout if done is not None and done.returncode == 0 else None


def traffic_unavailable() -> Optional[str]:
    """None when ``ss`` is here; else why not, in one sentence for a person."""
    return None if _first(SS_COMMANDS) else "The network monitor needs the ss command (the iproute2 package) on Linux."


def connection_table() -> Optional[str]:
    """Every connection as ``nettop``'s CSV (see :func:`render_connections`); None when ``ss`` failed."""
    text = _tool_text(SS_COMMANDS, SS_CONNECTIONS_ARGS, TIMEOUT_SECONDS)
    return render_connections(text) if text is not None else None


def listening_table() -> str:
    """Every listening TCP socket as ``lsof -F pcn`` ("" when ``ss`` cannot run)."""
    text = _tool_text(SS_COMMANDS, SS_LISTENING_ARGS, TIMEOUT_SECONDS)
    return render_listeners(text) if text is not None else ""


def routing_table(proc_root: str = PROC_ROOT) -> str:
    """The default routes as ``netstat -rn`` ``default`` rows ("" when the tables cannot be read)."""
    v4, v6 = (proc_root + table.removeprefix(PROC_ROOT) for table in (ROUTES_V4, ROUTES_V6))
    return render_routes(_small(v4), _small(v6))


def _small(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_ROUTES_BYTES).decode("ascii", "replace")
    except OSError:
        return ""


def process_table() -> Optional[str]:
    """``ps -eo pid=,ppid=,%cpu=,rss=,args=`` (rss in KiB, as on macOS); None when it failed."""
    return _tool_text(PS_COMMANDS, ("-eo", "pid=,ppid=,%cpu=,rss=,args="), TIMEOUT_SECONDS)


def process_paths(timeout: float = TIMEOUT_SECONDS, proc_root: str = PROC_ROOT) -> str:
    """``pid path`` per process, as macOS's ``ps -axo pid=,comm=``: the executable from
    ``/proc/<pid>/exe``, or — for another user's process, whose link may not be read — its
    ``cmdline``'s first word when that is a path. *timeout* is unused (nothing is run)."""
    lines = []
    try:
        pids = sorted(int(name) for name in os.listdir(proc_root) if name.isdigit())
    except OSError:
        return ""
    for pid in pids:
        path = _exe(proc_root, pid)
        if path:
            lines.append(f"{pid} {path}")
    return "\n".join(lines) + ("\n" if lines else "")


def _exe(proc_root: str, pid: int) -> str:
    try:
        return os.readlink(f"{proc_root}/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        pass
    try:
        with open(f"{proc_root}/{pid}/cmdline", "rb") as handle:
            first = handle.read(4096).split(b"\0", 1)[0].decode("utf-8", "replace")
    except OSError:
        return ""
    return first if first.startswith("/") else ""


def code_signature(path: str) -> Optional[str]:
    """None: Linux programs carry no code signature to display (phase 2: package ownership)."""
    return None


def tailscale_status() -> Optional[str]:
    """``tailscale status --json`` when Tailscale is installed and answers; else None."""
    return _tool_text(TAILSCALE_COMMANDS, ("status", "--json"), TAILSCALE_TIMEOUT_SECONDS)


# --- rendering (pure) -------------------------------------------------------------------------


def _endpoint(text: str) -> tuple[str, str]:
    """(address, port) of one ss endpoint: ``127.0.0.53%lo:53``, ``[fe80::1]%eth0:5353``,
    ``[::ffff:1.2.3.4]:443`` (→ ``1.2.3.4``), ``*:*``. The interface suffix is dropped."""
    host, _, port = text.rpartition(":")
    host = host.split("%", 1)[0].strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host, port
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip), port


def _family(addresses: str) -> str:
    """``6`` when either end is an IPv6 address (after mapped IPv4 was unwrapped), else ``4``."""
    return "6" if ":" in addresses else "4"


@dataclass
class _Socket:
    """One socket line of ss output, with its ``-i`` info line's byte counters."""

    netid: str
    state: str
    local: str
    peer: str
    users: list[tuple[str, int]]
    counters: dict[str, int] = field(default_factory=dict)


def _sockets(text: str) -> list[_Socket]:
    """Each socket of ss output with its continuation (``-i``) line's counters folded in."""
    sockets: list[_Socket] = []
    for line in text.splitlines():
        if line[:1].isspace():   # ss -i's info line belongs to the socket above it
            if sockets:
                sockets[-1].counters.update((name, int(value)) for name, value in _COUNTER.findall(line))
            continue
        words = line.split()
        # ss leaves the Netid column out when one protocol was asked for (-ltnpH).
        netid = words.pop(0) if words and words[0] in _NETIDS else "tcp"
        if len(words) < 5:
            continue
        users = [(name.replace("\\", ""), int(pid)) for name, pid in _USER.findall(" ".join(words[5:]))]
        sockets.append(_Socket(netid=netid, state=words[0], local=words[3], peer=words[4], users=users))
    return sockets


def _nettop_endpoint(address: str, port: str, family: str) -> str:
    return f"{address}{'.' if family == '6' else ':'}{port}"


def render_connections(text: str) -> str:
    """``ss -tuanpiH`` output as ``nettop -L 1 -x -n -J state,bytes_in,bytes_out`` CSV: per
    process (its first named owner) a ``name.pid,,in,out,`` row, then each socket's
    ``tcp4 local<->remote,State,in,out,`` row. An unconnected UDP socket and a socket with no
    process this user may see are left out (nettop's parser would skip them too)."""
    rows: dict[int, tuple[str, list[str], list[int]]] = {}
    for socket in _sockets(text):
        if not socket.users or (socket.netid == "udp" and socket.state == "UNCONN"):
            continue
        local_ip, local_port = _endpoint(socket.local)
        remote_ip, remote_port = _endpoint(socket.peer)
        family = _family(local_ip + remote_ip)
        protocol = "quic" if socket.netid == "udp" and remote_port == str(QUIC_PORT) else socket.netid
        bytes_in = socket.counters.get("bytes_received", 0)
        bytes_out = socket.counters.get("bytes_sent", socket.counters.get("bytes_acked", 0))
        state = NETTOP_STATES.get(socket.state, "") if socket.netid == "tcp" else ""
        name, pid = socket.users[0]
        _name, lines, totals = rows.setdefault(pid, (name, [], [0, 0]))
        lines.append(f"{protocol}{family} {_nettop_endpoint(local_ip, local_port, family)}<->"
                     f"{_nettop_endpoint(remote_ip, remote_port, family)},{state},{bytes_in},{bytes_out},")
        totals[0] += bytes_in
        totals[1] += bytes_out
    out = [NETTOP_HEADER]
    for pid, (name, lines, totals) in sorted(rows.items()):
        out.append(f"{name.replace(',', ' ')}.{pid},,{totals[0]},{totals[1]},")
        out.extend(lines)
    return "\n".join(out) + "\n"


def render_listeners(text: str) -> str:
    """``ss -ltnpH`` output as ``lsof -nP -iTCP -sTCP:LISTEN -F pcn``: ``p<pid>``, ``c<name>``,
    then ``n<address>:<port>`` per socket (``*`` for every interface, IPv6 in brackets). A socket
    shared by several processes is listed under each, as lsof does."""
    found: dict[int, tuple[str, list[str]]] = {}
    for socket in _sockets(text):
        if socket.state != "LISTEN":
            continue
        address, port = _endpoint(socket.local)
        shown = "*" if address in _ANY else (f"[{address}]" if ":" in address else address)
        for name, pid in socket.users:
            names = found.setdefault(pid, (name, []))[1]
            if f"{shown}:{port}" not in names:
                names.append(f"{shown}:{port}")
    out = []
    for pid, (name, names) in sorted(found.items()):
        out += [f"p{pid}", f"c{name}", *(f"n{entry}" for entry in names)]
    return "\n".join(out) + ("\n" if out else "")


def render_routes(route4: str, route6: str) -> str:
    """The default routes of ``/proc/net/route`` (gateway in little-endian hex) and
    ``/proc/net/ipv6_route`` (next hop in hex) as ``netstat -rn`` rows (``default 192.168.1.1
    eth0``). A default route with no gateway (a VPN's ``default dev wg0``, IPv6's ``unreachable``
    default on ``lo``) names none, like netstat's ``link#``."""
    out = []
    for line in route4.splitlines()[1:]:
        words = line.split()
        if len(words) >= 8 and words[1] == "00000000" and words[7] == "00000000" and _hex(words[3]) & RTF_GATEWAY:
            gateway = _hex(words[2])
            if gateway:
                out.append(f"default {ipaddress.IPv4Address(gateway.to_bytes(4, 'little'))} {words[0]}")
    for line in route6.splitlines():
        words = line.split()
        if len(words) >= 10 and words[0] == "0" * 32 and words[1] == "00" and _hex(words[4]):
            out.append(f"default {ipaddress.IPv6Address(bytes.fromhex(words[4]))} {words[9]}")
    return "\n".join(out) + ("\n" if out else "")


def _hex(text: str) -> int:
    try:
        return int(text, 16)
    except ValueError:
        return 0
