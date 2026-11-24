"""On a Linux server with no password dialog, a held weakening is confirmed from the person's own
terminal with their sudo password — never by the page or an agent (KI-659, design F9).

Linux round L1 (Ubuntu 24.04 server, core eb71c1d03c): turning Network Shield off answered 428,
and ``POST /api/approvals/confirm`` answered 403 "not confirmed" in 66 ms with no prompt at all —
``pkexec`` is not installed on a server, and no companion app runs on Linux. The person could only
edit config.yaml by hand.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from plugins.blackbox import approvals
from plugins.blackbox.approvals import terminal
from plugins.blackbox.approvals.store import Approvals
from plugins.blackbox.detection.paths import guard_commands


def test_the_held_message_names_blackbox_approve_where_there_is_no_dialog(monkeypatch):
    from plugins.blackbox.dashboard import approval_routes
    monkeypatch.setattr(terminal.platform, "system", lambda: "Linux")
    monkeypatch.setattr(terminal.system_prompt, "available", lambda: False)
    assert terminal.needed() and "blackbox approve" in approval_routes.not_paired()
    monkeypatch.setattr(terminal.system_prompt, "available", lambda: True)
    assert not terminal.needed() and approval_routes.not_paired() == approval_routes.NOT_PAIRED


class Tty:
    """A terminal: what the person types, and what was shown (kept apart, as on a real one)."""

    def __init__(self, typed: str) -> None:
        self._typed, self.shown = io.StringIO(typed), io.StringIO()

    def readline(self) -> str:
        return self._typed.readline()

    def write(self, text: str) -> int:
        return self.shown.write(text)

    def flush(self) -> None:
        pass


def _store_with_one() -> tuple[Approvals, str]:
    store = Approvals()
    held = store.hold("/api/settings", b'{"x": 1}', ["Network Shield: off"])
    return store, held.id


def test_a_challenge_is_one_time_and_only_roots_proof_approves(tmp_path):
    store, request_id = _store_with_one()
    nonce = store.challenge(request_id)
    assert nonce and store.challenge(request_id) is None, "one prompt per held request"
    folder = tmp_path / "approvals"
    folder.mkdir()
    (folder / request_id).write_text(nonce, encoding="utf-8")   # written by the person, not root
    assert not store.confirm_from_terminal(request_id, lambda rid, n: terminal.proved(folder, rid, n)), "a user's file is no proof"
    assert store.waiting() and store.waiting()[0].approved_at is None


def test_roots_file_with_the_challenge_approves(monkeypatch, tmp_path):
    store, request_id = _store_with_one()
    nonce = store.challenge(request_id)
    folder = tmp_path / "approvals"
    folder.mkdir(mode=0o755)
    (folder / request_id).write_text(nonce, encoding="utf-8")
    real_lstat = os.lstat
    monkeypatch.setattr(terminal.os, "lstat", lambda path: _as_root(real_lstat(path)))
    assert terminal.proved(folder, request_id, nonce) and not terminal.proved(folder, request_id, "other")
    assert not terminal.proved(folder, "../etc", nonce), "an id is never a path"
    assert store.confirm_from_terminal(request_id, lambda rid, n: terminal.proved(folder, rid, n))
    assert store.consume("/api/settings", b'{"x": 1}'), "the exact held change may now go through, once"


def _as_root(result: os.stat_result) -> os.stat_result:
    fields = list(result)
    fields[4] = 0   # st_uid
    return os.stat_result(fields)


def test_blackbox_approve_asks_on_the_terminal_and_proves_through_sudo(monkeypatch):
    calls, posted = [], []
    answers = {"/api/session": {"token": "t"}, "/api/companion/approvals": {"waiting": [{"id": "abc123", "reasons": ["DNS Shield: off"]}]},
               "/api/approvals/terminal-challenge": {"ok": True, "nonce": "n0nce", "folder": "/var/lib/blackbox/approvals"},
               "/api/approvals/terminal-confirm": {"ok": True}}
    monkeypatch.setattr(approvals.approve_command, "_call", lambda url, path, token, body=None: posted.append(path) or answers[path])

    class Session(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(approvals.approve_command.urllib.request, "urlopen", lambda *a, **k: Session(b'{"token": "t"}'))
    tty = Tty("y\n")
    code = approvals.approve_command.approve("http://127.0.0.1:9700", tty, run=lambda argv, _tty: calls.append(argv) or 0)
    assert code == 0 and posted[-1] == "/api/approvals/terminal-confirm"
    assert calls[0] == ["-k"] and calls[1][:2] == ["/bin/sh", "-c"] and calls[1][-3:] == ["/var/lib/blackbox/approvals", "abc123", "n0nce"]
    assert calls[-1] == ["-k"], "sudo forgets the password again"


def test_saying_no_proves_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(approvals.approve_command, "_call", lambda url, path, token, body=None:
                        {"waiting": [{"id": "abc123", "reasons": ["x"]}]} if path.endswith("approvals") else {"ok": True})

    class Session(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(approvals.approve_command.urllib.request, "urlopen", lambda *a, **k: Session(b'{"token": "t"}'))
    assert approvals.approve_command.approve("http://x", Tty("\n"), run=lambda argv, _tty: calls.append(argv) or 0) == 0
    assert calls == []


@pytest.mark.parametrize("command", ["blackbox approve", "hermes blackbox approve", "echo y | blackbox approve"])
def test_an_agent_may_not_run_blackbox_approve(command):
    assert guard_commands.switches_off(command)


#: The child: a new session whose ONLY terminal is the pty (stdin/stdout are not it), then
#: `blackbox approve`'s own entry with the dashboard part replaced by one question on the terminal.
_CHILD = """
import fcntl, os, sys, termios
os.setsid()
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
from plugins.blackbox.approvals import approve_command as command
def approve(url, tty):
    print("Approve this change? [y/N] ", end="", file=tty, flush=True)
    answer = tty.readline().strip()
    print(f"ANSWER={answer} FD={tty.fileno() >= 0}", file=tty, flush=True)
    return 0 if answer == "y" else 1
command.approve = approve
sys.exit(command.cmd_approve(None))
"""


def _read_until(master: int, wanted: bytes, seconds: float = 20.0) -> bytes:
    import select
    import time
    seen, deadline = b"", time.monotonic() + seconds
    while wanted not in seen and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], max(0.0, deadline - time.monotonic()))
        if not ready:
            break
        try:
            chunk = os.read(master, 4096)
        except OSError:   # Linux: the child closed its side
            break
        if not chunk:
            break
        seen += chunk
    return seen


def _drain_until_exit(master: int, child, seconds: float = 30.0) -> bytes:
    """Everything the child writes to its terminal until it exits. WHY keep reading: a process
    closing its terminal waits until what it wrote there is read (macOS drains a tty on close), so
    a test that stops reading and waits could hang the child it waits for."""
    import select
    import time
    seen, deadline = b"", time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.1)
        chunk = b""
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:   # Linux: the child closed its side
                chunk = b""
            seen += chunk
        if child.poll() is not None and not chunk:   # exited, and nothing more to read
            break
    if child.poll() is None:
        child.kill()
    child.wait(timeout=5)
    return seen


@pytest.mark.skipif(os.name != "posix", reason="a pty")
def test_blackbox_approve_opens_a_real_terminal_and_reads_the_answer_typed_there():
    """KI-673 (Linux round L2): in the person's own SSH terminal `blackbox approve` said "needs your
    own terminal" and exited 2 — ``open('/dev/tty', 'r+')`` raises "not seekable" on EVERY
    terminal, and the fake tty of the tests above never opened one. Here a REAL pty is the child's
    controlling terminal (LES-153), and what is typed there is the answer."""
    import pty
    import subprocess
    import sys
    master, slave = pty.openpty()
    child = subprocess.Popen([sys.executable, "-c", _CHILD, os.ttyname(slave)], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=Path(__file__).resolve().parents[2])
    try:   # the slave stays open here until the end: closed before the child opens it, macOS ends the pty
        asked = _read_until(master, b"[y/N] ")
        assert b"Approve this change?" in asked, (asked, child.stdout.read() if child.poll() is not None else b"")
        os.write(master, b"y\n")
        shown = _drain_until_exit(master, child)
        assert child.returncode == 0, (shown, child.stdout.read())
        assert b"ANSWER=y FD=True" in shown
    finally:
        os.close(master)
        os.close(slave)
        if child.poll() is None:
            child.kill()
