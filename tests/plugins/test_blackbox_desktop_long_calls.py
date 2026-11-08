"""Dashboard calls that outlast Hermes Desktop's 30 s request limit (desktop/long_calls.py), 2026-11-07.

Desktop drops a plugin request after 30 s, and an assistant turn or a Playground test can take
longer, so those calls start in the background and are read back by id. Checked here: only the
long routes start; a call answers "running" until the dashboard answers, then hands back that
answer unchanged; at most MAX_RUNNING run at once; records expire and are trimmed without
dropping a running one; a fault in the call still ends it. And the Desktop routes run every
dashboard call off Hermes' event loop — a blocking call there blanked the whole page while one
assistant turn ran.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import threading
import types
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox import desktop
from plugins.blackbox.desktop.dashboard_link import LinkAnswer
from plugins.blackbox.desktop.long_calls import LongCalls
from tests.waiting import wait_until

# The package exports a long_calls() function under the same name, so take the module by its path.
long_calls_mod = importlib.import_module("plugins.blackbox.desktop.long_calls")
PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"


class _GatedLink:
    """A DashboardLink stand-in whose POSTs wait until the test opens the gate."""

    def __init__(self, answer: LinkAnswer | None = None) -> None:
        self.gate = threading.Event()
        self.calls: list[tuple[str, str, object]] = []
        self.answer = answer or LinkAnswer(200, {"ok": True, "answer": "There are 3 open findings."})

    def forward(self, method, path, query="", body=None):
        self.calls.append((method, path, body))
        self.gate.wait(10)
        return self.answer


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_a_route_that_answers_quickly_is_not_started_in_the_background():
    calls = LongCalls(_GatedLink())
    assert calls.start("api/settings", {}).status == 404
    assert calls.start("api/session", {}).status == 404


def test_a_call_runs_until_the_dashboard_answers_then_hands_back_that_answer():
    link = _GatedLink()
    calls = LongCalls(link)

    started = calls.start("api/blackbox-chat", {"message": "What needs attention?"})
    call_id = started.body["call_id"]

    assert started.status == 202 and started.body["running"] is True
    assert calls.result(call_id) == LinkAnswer(202, {"running": True})
    link.gate.set()
    answer = wait_until(lambda: calls.result(call_id).status == 200 and calls.result(call_id), what="call finished")
    assert answer.body == {"ok": True, "answer": "There are 3 open findings."}
    assert link.calls == [("POST", "api/blackbox-chat", {"message": "What needs attention?"})]


def test_an_unknown_call_is_a_404():
    assert LongCalls(_GatedLink()).result("nope").status == 404


def test_no_more_than_max_running_calls_run_at_once():
    link = _GatedLink()
    calls = LongCalls(link)
    for _ in range(long_calls_mod.MAX_RUNNING):
        assert calls.start("api/playground/run", {"kind": "domain"}).status == 202

    refused = calls.start("api/playground/run", {"kind": "domain"})

    assert refused.status == 429
    link.gate.set()


def test_a_finished_call_expires_after_keep_s():
    link = _GatedLink()
    link.gate.set()
    clock = _Clock()
    calls = LongCalls(link, clock=clock)
    call_id = calls.start("api/blackbox-chat", {"message": "hi"}).body["call_id"]
    wait_until(lambda: calls.result(call_id).status == 200, what="call finished")

    clock.now += long_calls_mod.KEEP_S + 1

    assert calls.result(call_id).status == 404


def test_trimming_drops_finished_calls_and_keeps_running_ones(monkeypatch):
    monkeypatch.setattr(long_calls_mod, "MAX_KEPT", 2)
    monkeypatch.setattr(long_calls_mod, "MAX_RUNNING", 5)
    finished_link = _GatedLink()
    finished_link.gate.set()
    clock = _Clock()
    calls = LongCalls(finished_link, clock=clock)
    old = calls.start("api/blackbox-chat", {"message": "1"}).body["call_id"]
    wait_until(lambda: calls.result(old).status == 200, what="first call finished")
    finished_link.gate.clear()      # the next calls stay running
    clock.now += 1
    running = [calls.start("api/blackbox-chat", {"message": str(n)}).body["call_id"] for n in (2, 3)]

    assert calls.result(old).status == 404
    assert [calls.result(call_id).status for call_id in running] == [202, 202]
    finished_link.gate.set()


def test_a_fault_in_the_call_still_ends_it():
    class _Broken:
        def forward(self, *args, **kwargs):
            raise RuntimeError("boom")

    calls = LongCalls(_Broken())
    call_id = calls.start("api/blackbox-chat", {"message": "hi"}).body["call_id"]

    answer = wait_until(lambda: calls.result(call_id).status == 500 and calls.result(call_id), what="call ended")
    assert "RuntimeError" in answer.body["error"]


# --------------------------------------------------------------------------- the Desktop routes


def _client() -> TestClient:
    """Mount dashboard/plugin_api.py the way Hermes does: a standalone file, no package around it."""
    name = "hermes_dashboard_plugin_blackbox_long_calls_test"
    spec = importlib.util.spec_from_file_location(name, PLUGIN / "dashboard" / "plugin_api.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    app = FastAPI()
    app.include_router(module.router, prefix="/api/plugins/blackbox")
    return TestClient(app)


def _on_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def test_a_forwarded_dashboard_call_runs_off_hermes_event_loop(monkeypatch):
    seen: list[bool] = []

    def forward(method, path, query="", body=None):
        seen.append(_on_event_loop())
        return LinkAnswer(200, {"path": path})

    monkeypatch.setattr(desktop, "dashboard_link", lambda: types.SimpleNamespace(forward=forward))

    answer = _client().get("/api/plugins/blackbox/dash/api/graph-status")

    assert answer.status_code == 200 and answer.json() == {"path": "api/graph-status"}
    assert seen == [False]


def test_the_desktop_routes_start_a_long_call_and_read_it_back(monkeypatch):
    link = _GatedLink()
    calls = LongCalls(link)
    monkeypatch.setattr(desktop, "long_calls", lambda: calls)
    client = _client()

    started = client.post("/api/plugins/blackbox/dash-call/api/blackbox-chat", json={"message": "hi"})
    call_id = started.json()["call_id"]

    assert started.status_code == 202
    assert client.get(f"/api/plugins/blackbox/dash-call/{call_id}").json() == {"running": True}
    link.gate.set()
    wait_until(lambda: client.get(f"/api/plugins/blackbox/dash-call/{call_id}").status_code == 200, what="answer")
    assert client.get(f"/api/plugins/blackbox/dash-call/{call_id}").json()["answer"] == "There are 3 open findings."
