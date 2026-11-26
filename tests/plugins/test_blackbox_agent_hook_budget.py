"""A coding agent's hook answers inside its budget whatever the dashboard does, and never with a
weaker verdict because the dashboard was slow (``agent_hooks.protect.asking``).

Linux round L7 (BB-LINUX-PENDING-7582d0, Medium): on the busy VM Gemini CLI said "Hook timed out
after 10000ms" — the dashboard did not answer, the runner's own judgement (the plugin's, with the
same verified-graph lookup) then took 15 s, and Gemini, which RUNS a call once it stops waiting,
installed the graph-listed ``easy-day-js@1.11.21``. Every agent is told to wait 10 s; the runner
now answers by ``BUDGET_SECONDS`` (6.5 s): the dashboard first, then its own judgement, a tool call
not judged by then refused — and a locally judged event is recorded after the answer, off the
critical path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from plugins.blackbox import agent_hooks, audit
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events, judge_here, runner
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks as guard_hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset
from tests.waiting import wait_until

LISTED = "npm:easy-day-js@1.11.21"
RULES = {LISTED: {"identifier": "dep:npm:easy-day-js@1.11.21", "severity": "critical", "kind": "malware",
                  "name": "SafeDep malicious package: npm/easy-day-js@1.11.21", "source": "public"}}
DOWN = "http://127.0.0.1:9"   # nothing listens on the discard port
INSTALL = {"session_id": "l7-gm", "cwd": "/tmp", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
           "tool_input": {"command": "npm install easy-day-js@1.11.21"}, "tool_call_id": "c1"}


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    rules = Ruleset()
    rules.dependency = dict(RULES)
    monkeypatch.setattr(guard_hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False, discover=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: rules)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    events._answered.clear()
    return tmp_path


def _run(monkeypatch, capsys, url: str, payload: dict) -> tuple[int, str, float]:
    monkeypatch.setattr(runner.sys, "stdin", type("In", (), {"buffer": type("B", (), {"read": lambda self, n: json.dumps(payload).encode()})()})())
    began = time.monotonic()
    code = runner.main(["runner.py", "gemini-cli", "pre_tool", url])
    return code, capsys.readouterr().out, time.monotonic() - began


def _refused(out: str) -> bool:
    return json.loads(out).get("decision") == "deny"


def test_with_the_dashboard_stopped_a_graph_listed_package_is_still_refused_in_budget(machine, monkeypatch, capsys):
    _code, out, took = _run(monkeypatch, capsys, DOWN, INSTALL)
    assert _refused(out) and "easy-day-js" in out, out
    assert took < judge_here.BUDGET_SECONDS
    rows = [row for row in audit.read_findings(limit=20) if row.get("identifier") == RULES[LISTED]["identifier"]]
    assert rows and rows[0]["framework"] == "gemini-cli"      # recorded after the answer, not lost


class _SlowDashboard(BaseHTTPRequestHandler):
    """Answers its session at once and each event only after the runner stopped waiting for it."""

    def do_GET(self):
        self._send({"token": "t"})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        threading.Event().wait(judge_here.TIMEOUT_SECONDS + 1.0)   # slower than the runner's share for it
        self._send({"decision": "allow"})

    def _send(self, data):
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def test_a_slow_dashboard_never_weakens_the_verdict(machine, monkeypatch, capsys):
    """The dashboard that answers too late is not waited for past its share of the budget; the
    runner's own judgement — the same checks, the same graph rules — refuses the listed package."""
    server = HTTPServer(("127.0.0.1", 0), _SlowDashboard)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _code, out, took = _run(monkeypatch, capsys, f"http://127.0.0.1:{server.server_port}", INSTALL)
    finally:
        server.shutdown()
    assert _refused(out), out
    assert judge_here.TIMEOUT_SECONDS - 0.2 < took < judge_here.BUDGET_SECONDS


# --- the installed runner copy, as an agent runs it --------------------------------------------

STUCK_EVENTS = '''
import threading
def judge(body):
    threading.Event().wait(600)   # a judgement that never finishes in time (an overloaded machine)
def bookkeep(judged):
    pass
'''

SLOW_RECORD_EVENTS = '''
import os, threading
def judge(body):
    return {"decision": "block", "message": "refused by the judgement"}, "judged"
def bookkeep(judged):
    threading.Event().wait(5)   # recording that takes long: the agent must not wait for it
    with open(os.environ["RECORDED_MARK"], "w", encoding="utf-8") as mark:
        mark.write(judged)
'''


def _fake_plugin(tmp_path: Path, events_source: str) -> Path:
    plugin = tmp_path / "fake-plugin"
    (plugin / "agent_hooks" / "protect").mkdir(parents=True)
    for package in (plugin / "agent_hooks", plugin / "agent_hooks" / "protect"):
        (package / "__init__.py").write_text("", encoding="utf-8")
    (plugin / "agent_hooks" / "protect" / "events.py").write_text(events_source, encoding="utf-8")
    return plugin


def _installed_runner(plugin: Path) -> Path:
    folder = Path(agent_hooks._runner()).parent
    (folder / judge_here.JUDGE_HERE_FILE).write_text(json.dumps({"plugin": str(plugin)}), encoding="utf-8")
    return folder / "runner.py"


def _hook(script: Path, env: dict) -> tuple[subprocess.CompletedProcess, float]:
    began = time.monotonic()
    done = subprocess.run([sys.executable, str(script), "gemini-cli", "pre_tool", DOWN], input=json.dumps(INSTALL),
                          capture_output=True, text=True, timeout=60, env={**os.environ, **env}, check=False)
    return done, time.monotonic() - began


def test_a_call_the_runner_could_not_judge_in_time_is_refused_never_left_to_run(machine):
    """The agent stops waiting at 10 s and then RUNS the call: the runner answers first, and the
    answer for a call it could not judge is a refusal."""
    done, took = _hook(_installed_runner(_fake_plugin(machine, STUCK_EVENTS)), {})
    assert json.loads(done.stdout)["decision"] == "deny" and "could not check this action in time" in done.stdout
    assert took < judge_here.BUDGET_SECONDS + 2.0   # an interpreter's start and exit on top of the budget
    assert took < 10.0                          # inside the 10 s every agent is told to wait


def test_recording_a_locally_judged_call_never_delays_its_answer(machine):
    mark = machine / "recorded"
    done, took = _hook(_installed_runner(_fake_plugin(machine, SLOW_RECORD_EVENTS)), {"RECORDED_MARK": str(mark)})
    assert json.loads(done.stdout)["decision"] == "deny" and took < 4.0     # the 5 s record ran after the answer
    wait_until(mark.exists, timeout=30)
    assert mark.read_text(encoding="utf-8") == "judged"                     # and it was not lost
