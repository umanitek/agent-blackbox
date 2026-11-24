"""Sandbox permissions — the probe-gated permissions: services on this Mac (``local-ports``), the
clipboard, the keychain, camera and microphone; and ssh to this Mac by any of its addresses
(KI-621) (plugins/blackbox/shields/files/sandbox/platform/macos/profile.py; design "Sandbox
permissions" 2026-11-23, build step 16, local-only).

Each contract below is a REAL Seatbelt run on this Mac (a sandbox-exec'd child only; the
listeners are this test's own sockets), proven before the permission is offered:

* local-ports blocked: a service on this Mac is refused, a listed port and Blackbox's dashboard
  port stay reachable — every time (probe: an allow list FOLLOWED by a deny let ports through only
  sometimes, so the reachable ports are rendered after the never-list) — and Docker's TCP port and
  ssh's are never reopened; a rule listing port 22 is refused;
* Seatbelt's ``localhost`` filter also matches every address of this Mac (probe, macOS 27.2): a
  ``localhost:<port>`` rule refuses that port on the Mac's own network addresses too — which is
  why the never-list's ``localhost:22`` already refuses ``ssh <this Mac's LAN IP>`` (KI-621;
  Seatbelt itself refuses any other host: "host must be * or localhost");
* clipboard blocked: ``pbpaste`` fails at once (no hang) — the clipboard is never read here;
* keychain and camera/microphone are NOT offered until their effect is proven on a real service
  (round-7 VM): no rule is accepted, nothing is rendered for them;
* the hook reads a refused connect to this Mac as the local-ports refusal.

Red on the base ed4152ceac: no local-ports or clipboard permission existed.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import threading

import pytest

from plugins.blackbox.agent_hooks.protect import sandbox_errors
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.os_layout import machine_words
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.files.sandbox.permissions import Mode, Rule, Settings, catalogue
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")
CONNECT = ("import socket,sys\nfor port in sys.argv[2:]:\n try:\n  socket.create_connection((sys.argv[1], int(port)), timeout=2)"
           ".close(); print(port, 'open')\n except OSError as e: print(port, 'refused', e.errno)")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    return real


@pytest.fixture
def entry(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def _listen(host: str = "127.0.0.1", family: int = socket.AF_INET) -> socket.socket:
    server = socket.socket(family)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind((host, 0))
    server.listen(16)
    threading.Thread(target=lambda: [server.accept() for _ in range(16)], daemon=True).start()
    return server


def _sandboxed(profile: str, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([macos_profile.SANDBOX_EXEC, "-f", profile, *argv], capture_output=True, text=True, timeout=30, check=False)


@REAL
def test_blocked_local_ports_refuse_this_mac_but_the_listed_and_dashboard_ports(home, entry):
    listed, other, dashboard = _listen(), _listen(), _listen()
    try:
        ports = [server.getsockname()[1] for server in (listed, other, dashboard)]
        entry["dashboard_port"] = ports[2]
        entry["agent_sandbox"] = {"permissions": [{"permission": "local-ports", "mode": "block", "ports": [ports[0], 2375]}]}
        sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))
        profile = str(sandbox.layout.agent_profile("claude-code"))
        text = open(profile, encoding="utf-8").read()
        after = text.split(macos_profile.NEVER_MARK)[1].split(macos_profile.PORTS_MARK)[1]
        assert "localhost:2375" not in after and "localhost:22\"" not in after   # never reopened: Docker refused, ssh never
        for _ in range(5):   # probed: an allow list followed by a deny was let through only sometimes — hence allows last
            out = _sandboxed(profile, sys.executable, "-I", "-c", CONNECT, "127.0.0.1", *map(str, ports)).stdout.split("\n")
            assert out[:3] == [f"{ports[0]} open", f"{ports[1]} refused 1", f"{ports[2]} open"], out
    finally:
        for server in (listed, other, dashboard):
            server.close()


def _own_addresses() -> list[tuple[str, int]]:
    """This Mac's own addresses (v4 and global v6), read at test time: ``(address, family)``."""
    out = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=10, check=False).stdout
    found = [(match.group(1), socket.AF_INET) for match in re.finditer(r"\sinet (\d+\.\d+\.\d+\.\d+)", out)]
    found += [(match.group(1), socket.AF_INET6) for match in re.finditer(r"\sinet6 ([0-9a-f:]+)(?:\s|%)", out)
              if not match.group(1).startswith("fe80")]
    return found


@REAL
def test_a_localhost_rule_covers_every_address_of_this_mac(home):
    """KI-621: why ``ssh <this Mac's LAN IP>`` is refused by the never-list's ``localhost:22``."""
    server = _listen("::", socket.AF_INET6)
    try:
        port = server.getsockname()[1]
        profile = home / "probe.sb"
        profile.write_text(f'(version 1)\n(allow default)\n(deny network-outbound (remote ip "localhost:{port}"))\n', encoding="utf-8")
        addresses = _own_addresses()
        assert addresses, "this Mac has no address to probe"
        for address, _family in addresses:
            reachable = subprocess.run([sys.executable, "-I", "-c", CONNECT, address, str(port)], capture_output=True, text=True,
                                       timeout=30, check=False).stdout
            if "open" not in reachable:
                continue   # not reachable at all here (a tunnel without a route): nothing to prove
            assert "refused 1" in _sandboxed(str(profile), sys.executable, "-I", "-c", CONNECT, address, str(port)).stdout, address
    finally:
        server.close()
    by_address = home / "by-address.sb"
    by_address.write_text('(version 1)\n(allow default)\n(deny network-outbound (remote ip "192.168.1.10:22"))\n', encoding="utf-8")
    refused = _sandboxed(str(by_address), "/usr/bin/true")
    assert refused.returncode != 0 and "host must be * or localhost" in refused.stderr


@REAL
def test_blocked_clipboard_fails_at_once_without_a_hang(home, entry):
    entry["agent_sandbox"] = {"permissions": [{"permission": "clipboard", "mode": "block"}]}
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    done = _sandboxed(str(sandbox.layout.agent_profile("claude-code")), "/bin/sh", "-c", "/usr/bin/pbpaste >/dev/null; echo code=$?")
    assert "code=1" in done.stdout


def test_port_22_can_never_be_listed():
    errors: list = []
    permissions.validate_section({"permissions": [{"permission": "local-ports", "mode": "block", "ports": [22]}]}, errors)
    assert any(f"ssh into {machine_words()}" in error for error in errors)


@pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile is rendered on macOS")
def test_unproven_permissions_are_neither_accepted_nor_rendered(home):
    for permission in ("keychain", "camera-mic"):
        assert catalogue.BY_ID[permission].controllable is False
        errors: list = []
        permissions.validate_section({"permissions": [{"permission": permission, "mode": "block"}]}, errors)
        assert errors
    allowed = permissions.allowances(Settings(rules=(Rule("docker", Mode.ALLOW), Rule("tool-folders", Mode.ALLOW))))
    assert allowed.refused == frozenset() and macos_profile.permission_lines(allowed, str(home)) == []


def test_the_hook_reads_a_refused_connect_to_this_mac_as_local_ports():
    for output in ("psql: error: connection to server at \"localhost\" (127.0.0.1), port 5432 failed: Operation not permitted",
                   "curl: (7) Immediate connect fail for 127.0.0.1: Operation not permitted"):
        assert [each.kind for each in sandbox_errors.refusals(output)] == [sandbox_errors.LOCAL_PORT], output
