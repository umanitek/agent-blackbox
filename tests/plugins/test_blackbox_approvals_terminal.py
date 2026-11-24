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
