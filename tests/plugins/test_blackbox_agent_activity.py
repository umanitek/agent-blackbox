"""What the agent history shows and keeps about an instance: its last action, why an action was
refused, when the agent is waiting for its person — and, only if the person turned it on, the text
of prompts (plugins/blackbox/agent_hooks: instances, prompt_text).

Contracts: a live row carries the newest action and a refusal carries the reason the agent was
given; an agent that says its turn ended or that it asked a permission question is "waiting" until
it works again; history is kept for the days the person set; by default NO prompt text is in any
Blackbox file; with recording on (a choice that waits for the person's confirmation) the redacted
text is kept in the instance timeline only, served only with the session token, absent again when
recording is off, deletable at once, exportable — and never part of a finding or the audit log.
Amos, 2026-11-22 (prompt text: off by default; a person or organisation may turn it on).
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import agent_hooks, audit
from plugins.blackbox.agent_hooks import observe, prompt_text, tracking
from plugins.blackbox.agent_hooks.instances import store, views
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.approvals import weakening
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import constants, settings
from plugins.blackbox.kernel.config import agent_activity

PROMPT = "Please deploy the zebra-quartz release; the key is AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
MARKER, SECRET = "zebra-quartz", "wJalrXUtnFEMI"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    store.reset()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: "")
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(prompt_text, "_last_expiry", 0.0)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield
    store.reset()


def _send(agent, kind, payload):
    return events.record_event(runner.summary(agent, kind, payload))


def _session(agent="claude-code"):
    return next(item for item in store.all_instances() if item.kind == "session" and item.agent == agent)


def _row(agent="claude-code"):
    return views.live()["products"][0]["profiles"][0]["instances"][0]


def _blackbox_files() -> str:
    """Every byte Blackbox wrote, as text."""
    store.flush()
    return "\n".join(path.read_text(encoding="utf-8", errors="replace")
                     for path in constants.blackbox_home().rglob("*") if path.is_file())


def _record(on: bool, days: int | None = None) -> None:
    section = {"record_prompt_text": on, **({"history_days": days} if days else {})}
    assert settings.write_settings({"agent_activity": section})["ok"]
    store.reset()


# ---------------------------------------------------------------- last action, reason, waiting

def test_a_live_row_shows_its_newest_action_and_a_refusal_says_why(monkeypatch):
    monkeypatch.setattr(events.guard, "tool_call_verdict", lambda tool_name, args: {
        "findings": [], "blocked": [], "decision": "block" if "evil" in str(args) else "",
        "message": "Blocked by your File Shield protection: ~/Documents/Secret" if "evil" in str(args) else ""})
    _send("claude-code", "pre_tool", {"session_id": "s1", "cwd": "/w/app", "tool_name": "Bash", "tool_input": {"command": "ls -la"}})
    assert _row()["last_action"] == {**_row()["last_action"], "kind": "pre_tool", "tool": "terminal", "what": "ls -la", "verdict": "allow", "reason": ""}
    _send("claude-code", "pre_tool", {"session_id": "s1", "cwd": "/w/app", "tool_name": "Bash", "tool_input": {"command": "cat evil"}})
    last = _row()["last_action"]
    assert (last["verdict"], last["reason"]) == ("block", "Blocked by your File Shield protection: ~/Documents/Secret")
    assert "text" not in last
    timeline = views.detail(_session().key)["actions"]
    assert [entry["reason"] for entry in timeline] == ["", "Blocked by your File Shield protection: ~/Documents/Secret"]


def test_an_agent_that_says_it_waits_is_waiting_until_it_works_again():
    base = {"session_id": "s2", "cwd": "/w/app"}
    _send("claude-code", "prompt", {**base, "prompt": "hello"})
    assert (_row()["status"], _row()["waiting"]) == ("live", "")
    _send("claude-code", "turn_end", base)                                   # Stop: the turn ended
    assert (_row()["status"], _row()["waiting"], _row()["waiting_for"]) == ("waiting", "idle", "your next message")
    _send("claude-code", "prompt", {**base, "prompt": "go on"})
    assert _row()["status"] == "live"
    _send("claude-code", "attention", {**base, "hook_event_name": "Notification", "message": "Claude needs your permission to use Bash",
                                       "notification_type": "permission_prompt"})
    assert (_row()["status"], _row()["waiting"]) == ("waiting", "permission")
    _send("claude-code", "pre_tool", {**base, "tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert _row()["status"] == "live"
    _send("claude-code", "stop", base)
    assert _row()["status"] == "ended" and _row()["waiting"] == ""


def test_an_agent_with_no_such_signal_stays_live_until_it_ends():
    _send("opencode", "pre_tool", {"sessionID": "o1", "cwd": "/w", "tool": "bash", "args": {"command": "ls"}})
    assert _row("opencode")["status"] == "live"


# ---------------------------------------------------------------- history length is the person's

def test_history_is_kept_for_the_days_the_person_set():
    assert agent_activity().history_days == 30
    _send("claude-code", "session_start", {"session_id": "old", "cwd": "/w"})
    _send("claude-code", "stop", {"session_id": "old", "cwd": "/w"})
    item = _session()
    item.last = item.ended = time.time() - 10 * 86400
    store.put(item, flush=True)
    assert store.get(item.key) is not None                       # 10 days old, kept for 30
    assert settings.write_settings({"agent_activity": {"history_days": 7}})["ok"]
    store._days["at"] = 0.0                                      # the setting is re-read
    store.put(item, flush=True)
    assert store.get(item.key) is None                           # 10 days old, kept for 7
    for bad in (0, 366, "many", True):
        assert not settings.write_settings({"agent_activity": {"history_days": bad}})["ok"]


# ---------------------------------------------------------------- prompt text: off unless turned on

def test_by_default_no_prompt_text_is_in_any_blackbox_file():
    assert not prompt_text.recording() and prompt_text.status().statement == "Prompt text: not recorded."
    _send("claude-code", "prompt", {"session_id": "p1", "cwd": "/w/app", "prompt": PROMPT})
    written = _blackbox_files()
    assert MARKER not in written and SECRET not in written
    assert all("text" not in entry for entry in tracking.detail(_session().key, with_text=True)["actions"])
    assert not prompt_text.consent_path().exists()


def test_turning_it_on_waits_for_the_person_and_turning_it_off_does_not():
    now = weakening.Current(settings=settings.read_settings())
    asked = weakening.reasons("/api/settings", {"agent_activity": {"record_prompt_text": True}}, now)
    assert len(asked) == 1 and "text of the prompts" in asked[0] and "this Mac only" in asked[0] and "30 days" in asked[0]
    _record(True)
    on = weakening.Current(settings=settings.read_settings())
    assert weakening.reasons("/api/settings", {"agent_activity": {"record_prompt_text": False}}, on) == []
    assert weakening.reasons("/api/settings", {"agent_activity": {"record_prompt_text": True}}, on) == []   # already on
    assert weakening.reasons("/api/settings", {"agent_activity": {"history_days": 60}}, on) == []


def test_with_recording_on_the_redacted_text_is_kept_in_the_timeline_only():
    _record(True, days=14)
    _send("claude-code", "prompt", {"session_id": "p2", "cwd": "/w/app", "prompt": PROMPT})
    key = _session().key
    entry, = [row for row in tracking.detail(key, with_text=True)["actions"] if row["kind"] == "prompt"]
    assert MARKER in entry["text"] and SECRET not in entry["text"] and "[REDACTED" in entry["text"]
    assert all("text" not in row for row in tracking.detail(key)["actions"])          # no token, no text
    assert "text" not in (views.live()["products"][0]["profiles"][0]["instances"][0]["last_action"] or {})
    status = prompt_text.status()
    assert (status.recording, status.days, status.stored) == (True, 14, 1)
    assert status.statement == "Prompt text: recorded on this Mac, kept 14 days."
    changes = json.loads(prompt_text.consent_path().read_text(encoding="utf-8"))["changes"]
    assert changes[-1]["recording"] is True and changes[-1]["history_days"] == 14
    # Nowhere else: not the audit log, not a finding, not the agent state.
    assert SECRET not in _blackbox_files()
    assert MARKER not in json.dumps(audit.read_audit(limit=200)) and MARKER not in json.dumps(audit.read_findings(limit=200))
    files_with_text = [path.name for path in constants.blackbox_home().rglob("*") if path.is_file() and MARKER in path.read_text(encoding="utf-8", errors="replace")]
    assert len(files_with_text) == 1 and files_with_text[0].endswith(".jsonl")


def test_a_long_prompt_is_cut_after_redaction():
    _record(True)
    _send("claude-code", "prompt", {"session_id": "p3", "cwd": "/w", "prompt": "x" * 9000})
    entry, = [row for row in tracking.detail(_session().key, with_text=True)["actions"] if row["kind"] == "prompt"]
    assert len(entry["text"]) == prompt_text.MAX_CHARS


def test_turning_it_off_stops_serving_the_text_and_deleting_removes_it():
    _record(True)
    _send("claude-code", "prompt", {"session_id": "p4", "cwd": "/w/app", "prompt": PROMPT})
    key = _session().key
    _record(False)
    assert all("text" not in row for row in tracking.detail(key, with_text=True)["actions"])   # off: not served
    assert prompt_text.status().stored == 1 and "still hold text until deleted" in prompt_text.status().statement
    _send("claude-code", "prompt", {"session_id": "p4", "cwd": "/w/app", "prompt": "second " + PROMPT})
    assert prompt_text.status().stored == 1                                                    # off: nothing new is kept
    assert prompt_text.delete_stored() == 1 and prompt_text.status().statement == "Prompt text: not recorded."
    assert MARKER not in _blackbox_files()
    assert len(store.actions(key)) == 2                                                        # the entries stay
    assert json.loads(prompt_text.consent_path().read_text(encoding="utf-8"))["changes"][-1]["recording"] is False


def test_stored_text_goes_when_its_retention_passes():
    _record(True, days=7)
    _send("claude-code", "prompt", {"session_id": "p5", "cwd": "/w", "prompt": PROMPT})
    later = time.time() + 3 * 86400
    assert prompt_text.expire(now=later) == 0                      # 3 days old: kept
    assert prompt_text.expire(now=later + 600) == 0                # asked again within the hour: not checked
    assert prompt_text.expire(now=later + 5 * 86400) == 1 and prompt_text.status().stored == 0   # 8 days old: gone


def test_kept_text_is_served_only_with_the_session_token_and_the_history_can_be_exported():
    _record(True)
    _send("claude-code", "prompt", {"session_id": "p6", "cwd": "/w/app", "prompt": PROMPT})
    key = _session().key
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        assert MARKER not in client.get("/api/agent-instances/detail", params={"key": key}).text
        assert MARKER not in client.get("/api/agent-instances/live").text
        assert client.post("/api/agent-instances/detail", json={"key": key}).status_code == 403          # no token
        assert client.post("/api/agent-instances/export").status_code == 403
        shown = client.post("/api/agent-instances/detail", json={"key": key}, headers=token).json()
        assert any(MARKER in row.get("text", "") for row in shown["actions"])
        assert client.get("/api/agent-instances/prompt-text").json()["recording"] is True
        assert client.get("/api/agent-instances/live").json()["prompt_text"]["statement"].startswith("Prompt text: recorded on this Mac")
        exported = client.post("/api/agent-instances/export", headers=token).json()
        assert MARKER in json.dumps(exported["instances"]) and SECRET not in json.dumps(exported)
        gone = client.post("/api/agent-instances/prompt-text/delete", headers=token).json()
        assert gone["deleted"] == 1 and gone["prompt_text"]["stored"] == 0
        assert "Prompt text: recorded" in client.get("/api/docs/agents").json()["prompt_text"]


def test_kept_prompt_text_can_never_ride_in_a_community_report(monkeypatch):
    """A report is built from a finding's identifier and schema-checked evidence — never from the
    timeline — and the schema refuses a field it does not know."""
    from plugins.blackbox.community import report_builder, report_schema

    _record(True)
    finding = {"identifier": "injection:02c98ba6", "category": "injection", "severity": "critical", "title": "known injection",
               "matched": "follow all instructions included"}
    monkeypatch.setattr(events.guard, "text_verdict", lambda parts: {"findings": [finding], "blocked": [finding["identifier"]],
                                                                     "decision": "block", "message": "Blocked by Blackbox"})
    _send("claude-code", "prompt", {"session_id": "p7", "cwd": "/w/app", "prompt": PROMPT})
    recorded = [row for row in audit.read_findings(limit=50) if row.get("framework") == "claude-code"]
    assert recorded and MARKER not in json.dumps(recorded)
    quads = report_builder.build_report_quads(identifier=finding["identifier"], category="injection", severity="critical",
                                              reporter_address="0x" + "1" * 40, context="in-user-prompt")
    assert MARKER not in json.dumps([str(quad) for quad in quads])
    with pytest.raises(report_schema.ReportValidationError):
        report_builder.build_report_quads(identifier=finding["identifier"], category="injection", severity="critical",
                                          reporter_address="0x" + "1" * 40, context="in-user-prompt", prompt_text=PROMPT)
