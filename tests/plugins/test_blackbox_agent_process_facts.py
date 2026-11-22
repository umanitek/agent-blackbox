"""What a running process is: its program, its verified signature and whether the kernel
sandboxes it (KI-588 f: plugins/blackbox/agent_hooks/process_facts.py and the
``/api/agent-instances/process`` route). A companion add-on used to serve this itself; it is now
the core's answer, read from the kernel and the program, never from what the process says."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox.agent_hooks import process_facts
from plugins.blackbox.agent_hooks.observe import platform
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import code_signing
from tests.waiting import wait_until

MACOS = pytest.mark.skipif(sys.platform != "darwin" or not os.access("/usr/bin/sandbox-exec", os.X_OK),
                           reason="the kernel's sandbox answer needs macOS")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    process_facts.forget()
    monkeypatch.setattr(code_signing, "describe", lambda path, run=None: code_signing.Signer(kind="apple", signer="Apple", verified=True))
    yield
    process_facts.forget()


@MACOS
def test_the_kernel_says_which_process_runs_in_a_sandbox_and_which_program_it_is(monkeypatch):
    monkeypatch.setattr(code_signing, "entitlements", lambda path: "")
    child = subprocess.Popen(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/sleep", "30"])
    try:
        def started():
            found = process_facts.facts(child.pid)
            return found if found.path.endswith("/sleep") else None

        found = wait_until(started, what="sandbox-exec has started sleep")
        assert (found.found, found.sandboxed, found.app_sandbox, found.signer.kind) == (True, True, False, "apple")
        mine = process_facts.facts(os.getpid())
        assert mine.found and mine.path and mine.sandboxed is False
    finally:
        child.kill()
        child.wait()


def test_the_app_sandbox_entitlement_is_read_once_per_program_version_and_unknown_when_unreadable(tmp_path, monkeypatch):
    program = tmp_path / "app"
    program.write_bytes(b"\xcf\xfa\xed\xfe")
    asked = []
    xml = ('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
           '<key>com.apple.security.app-sandbox</key><true/></dict></plist>')
    monkeypatch.setattr(code_signing, "entitlements", lambda path: asked.append(path) or xml)
    assert process_facts._app_sandbox(str(program)) is True and process_facts._app_sandbox(str(program)) is True
    assert asked == [str(program)]
    process_facts.forget()
    monkeypatch.setattr(code_signing, "entitlements", lambda path: None)
    assert process_facts._app_sandbox(str(program)) is None   # codesign could not say: unknown, asked again next time


def test_the_route_answers_a_gone_process_honestly_and_refuses_a_bad_pid(monkeypatch):
    monkeypatch.setattr(platform, "process_path", lambda pid: "")
    client = TestClient(server.create_app(), base_url="http://127.0.0.1")
    assert client.get("/api/agent-instances/process?pid=99999").json() == {
        "pid": 99999, "path": "", "found": False, "sandboxed": None, "app_sandbox": None,
        "signer": {"kind": "unknown", "signer": "", "team": "", "verified": None, "notarised": False}}
    for bad in ("", "1", "abc", "-5"):
        assert client.get(f"/api/agent-instances/process?pid={bad}").status_code == 400
