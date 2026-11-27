"""Which process holds the client end of a loopback connection to Blackbox (every OS psutil reads).

A broker must know which agent asked. What the request says about itself — a ``pid`` in its body
— is the asking agent's to choose: Codex could name Claude Code's process and get Claude Code's
"allow" (independent review 2026-11-26, finding 6). The connection is not: the kernel knows which
process holds the socket whose local port is the client port the server saw, and no other process
can hold it. Only this user's processes are read (a broker's client is one of the person's).

Usage::

    peer_pid(Peer("127.0.0.1", 52344, 9700))   # 4242, or 0 when no process of this user holds it
    connection_pid(context.peer)               # the same, 0 for no peer or when it can not be read
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Iterable, Optional

import psutil

from ....shield_api import Peer

logger = logging.getLogger(__name__)
LOOPBACK = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1"})

Processes = Callable[[], Iterable[psutil.Process]]


def _mine() -> Iterable[psutil.Process]:
    me = getattr(os, "getuid", lambda: -1)()
    for process in psutil.process_iter(["uids"]):
        uids = process.info.get("uids")
        if uids is not None and uids.real == me:
            yield process


def peer_pid(peer: Peer, processes: Processes = _mine) -> int:
    """The pid of the one process holding the client end of *peer* (local port ``peer.port``,
    remote port ``peer.server_port``, both on loopback); 0 when none of this user's does."""
    if peer.host not in LOOPBACK or not 0 < peer.port < 65536 or not 0 < peer.server_port < 65536:
        return 0
    for process in processes():
        try:
            for connection in process.net_connections(kind="tcp"):
                local, remote = connection.laddr, connection.raddr
                if (local and remote and local.port == peer.port and remote.port == peer.server_port
                        and local.ip in LOOPBACK and remote.ip in LOOPBACK):
                    return process.pid
        except psutil.Error:   # gone, or not ours to read: not the asker
            continue
    return 0


def connection_pid(peer: Optional[Peer]) -> int:
    """:func:`peer_pid` for a call's connection (``ShieldContext.peer``); 0 when not known."""
    if peer is None:
        return 0
    try:
        return peer_pid(peer)
    except Exception:   # health: allow BLE001 -- the asker is then unknown, judged as every agent's
        logger.debug("blackbox: the process behind a brokered request could not be read", exc_info=True)
        return 0


__all__ = ["LOOPBACK", "connection_pid", "peer_pid"]
