"""Agent sandbox brokers — the asking agent is the process holding the request's connection, never
the pid the request names (plugins/blackbox/shields/files/sandbox/platform/peer_process.py,
brokered/asking.py, packages/__init__.py; independent review 2026-11-26, finding 6).

Contracts (red on the base 30b94edf83):
* a broker names the agent from the process holding the client end of the request's loopback
  connection; a ``pid`` in the body (another agent's) is never believed;
* with no connection known, the asker is unknown — never the body's pid;
* :func:`peer_pid` finds the real process holding a real loopback client socket (an in-test
  listener on 127.0.0.1, no outside network).
"""

from __future__ import annotations

import socket
import subprocess
import sys

from plugins.blackbox.shields.files.sandbox import packages
from plugins.blackbox.shields.files.sandbox.brokered.asking import Asking
from plugins.blackbox.shields.files.sandbox.platform import peer_process
from plugins.blackbox.shields.shield_api import InstanceRef, Peer, ShieldContext

CLAUDE_PID, CODEX_PID = 4242, 5353
OWNERS = {CLAUDE_PID: InstanceRef("claude-code", "claude-code:s1"), CODEX_PID: InstanceRef("codex", "codex:s1")}


def _context(peer=None):
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                         owner_of_pid=OWNERS.get, peer=peer)


def test_the_body_pid_never_names_the_asker(monkeypatch):
    peer = Peer("127.0.0.1", 52344, 9700)
    monkeypatch.setattr(peer_process, "peer_pid", lambda seen: CODEX_PID if seen == peer else 0)
    asked = Asking.of(_context(peer), {"pid": CLAUDE_PID, "cwd": "/tmp"})   # Codex names Claude Code's process
    assert asked.agent == "codex" and asked.pid == CODEX_PID
    assert packages._asker(_context(peer), {"pid": CLAUDE_PID}).agent == "codex"


def test_without_a_connection_the_asker_is_unknown():
    assert Asking.of(_context(), {"pid": CLAUDE_PID}).owner is None
    assert packages._asker(_context(), {"pid": CLAUDE_PID}) is None


def test_peer_pid_finds_the_process_holding_a_real_loopback_client_socket():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = subprocess.Popen([sys.executable, "-c", f"import socket,sys; s=socket.create_connection(('127.0.0.1', {port})); "
                               "print(s.getsockname()[1], flush=True); sys.stdin.read()"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        accepted, (host, client_port) = server.accept()
        assert int(client.stdout.readline()) == client_port
        assert peer_process.peer_pid(Peer(host, client_port, port)) == client.pid
        assert peer_process.peer_pid(Peer("10.0.0.5", client_port, port)) == 0   # not loopback: nobody
        accepted.close()
    finally:
        client.stdin.close()
        client.wait(timeout=30)
        server.close()
