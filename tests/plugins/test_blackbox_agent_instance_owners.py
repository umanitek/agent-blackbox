"""Which agent instance owns a File Shield refusal or a running process (KI-588:
plugins/blackbox/agent_hooks/owners.py, shields/files/events.hits, the
``/api/agent-instances/by-pid`` route).

A companion app's Activity view could only filter File Shield's hits by agent name and time, and
walked the process tree itself to find which instance a process belonged to. The core now answers
both: each hit names its instance (and sub-agent, where the hook said), an OS-sandbox refusal names
the instance it was attributed to, and a pid is answered from the tracker's own ancestry.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import audit
from plugins.blackbox.agent_hooks import observe, owners, tracking
from plugins.blackbox.agent_hooks.instances import store, sub_key
from plugins.blackbox.agent_hooks.protect import events as hook_events
from plugins.blackbox.dashboard import server
from plugins.blackbox.dashboard.shields_routes import api_routes
from plugins.blackbox.shields.files import changes, events as file_events, mode as files_mode
from plugins.blackbox.shields.files.protect import FILE_HIT_ID

VAULT = "~/Documents/Vault"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Documents" / "Vault").mkdir(parents=True)
    store.reset()
    changes.reset()
    owners.forget()
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    yield real
    store.reset()
    changes.reset()


def _refusing(monkeypatch, home):
    hit = {"identifier": FILE_HIT_ID, "category": "files", "severity": "critical", "title": "File Shield: protected",
           "source": "custom", "confirmed": False,
           "fields": {"item": VAULT, "path": str(home / "Documents" / "Vault" / "a.txt"), "route": "read"}}
    monkeypatch.setattr(hook_events.guard, "tool_call_verdict",
                        lambda **_k: {"findings": [hit], "blocked": [hit], "decision": "block", "message": "no"})


def test_a_hook_refusal_names_its_instance_and_its_sub_agent(home, monkeypatch):
    _refusing(monkeypatch, home)
    base = {"agent": "claude-code", "session": "s-1", "cwd": str(home / "proj")}
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "Read", "args": {"file_path": "x"}})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "Read", "args": {"file_path": "y"}, "sub": "agent-7",
                              "tool_call_id": "c2"})
    rows = file_events.hits(owner_of=api_routes.finding_owners())
    session = hook_events.session_key("claude-code", "s-1", str(home / "proj"))
    assert {row["instance"] for row in rows} == {session} and all(row["agent"] == "claude-code" for row in rows)
    assert sorted(row["sub_agent"] for row in rows) == ["", sub_key(session, "agent-7")]
    assert store.get(sub_key(session, "agent-7")) is not None   # the key a hit names is the tracker's own


def test_without_a_resolver_a_hit_still_lists_and_says_no_instance(home, monkeypatch):
    _refusing(monkeypatch, home)
    hook_events.record_event({"agent": "codex", "session": "x", "cwd": "/w", "event": "pre_tool", "tool_name": "shell",
                              "args": {"command": "cat a"}})
    [row] = file_events.hits()
    assert (row["agent"], row["instance"], row["sub_agent"]) == ("codex", "", "")


def test_a_kernel_refusal_names_the_instance_it_was_given_to_and_an_ungiven_one_none(home, monkeypatch):
    monkeypatch.setattr(hook_events.guard, "tool_call_verdict", lambda **_k: {"findings": [], "blocked": [], "decision": "", "message": ""})
    secret = str(home / "Documents" / "Vault" / "s.txt")
    mode = files_mode.build(enabled=True, protected=(VAULT,))
    changes.record([{"path": secret, "kind": "denied", "program": "python3", "ts": int(time.time()) - 3}], mode)
    assert [row["instance"] for row in file_events.hits(owner_of=api_routes.finding_owners())] == [""]   # nobody was live: not guessed
    base = {"agent": "gemini-cli", "session": "g-1", "cwd": str(home / "site"), "sandboxed": True}
    hook_events.record_event({**base, "event": "session_start"})
    hook_events.record_event({**base, "event": "pre_tool", "tool_name": "run_shell_command", "args": {"command": "python3 r.py"}})
    changes.record([{"path": secret + "2", "kind": "denied", "program": "python3", "ts": int(time.time()) + 1}], mode)
    rows = file_events.hits(owner_of=api_routes.finding_owners())
    session = hook_events.session_key("gemini-cli", "g-1", str(home / "site"))
    assert (rows[0]["agent"], rows[0]["instance"]) == ("gemini-cli", session)   # newest first: given to the live sandboxed run
    assert audit.read_findings(limit=5)[0]["framework"] == audit.SANDBOX_RECORDER   # the record itself is unchanged


def _client() -> TestClient:
    return TestClient(server.create_app(), base_url="http://127.0.0.1")


def test_a_pid_is_owned_by_the_live_instance_whose_agent_process_is_its_ancestor(home, monkeypatch):
    now = time.time()
    chain = [(900, 880, now, "python3 r.py"), (880, 500, now, "/bin/zsh -c python3 r.py"),
             (500, 1, now - 100, "/opt/homebrew/bin/claude -p hi")]
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: [row for row in chain if row[0] <= pid])
    session = store.Instance("claude-code:00aa", "claude-code", "session", now - 50, now, folder="proj", pid=500)
    store.put(session)
    client = _client()
    answer = client.get("/api/agent-instances/by-pid?pid=900").json()
    assert answer == {"pid": 900, "found": True, "agent": "claude-code", "instance": "claude-code:00aa", "sub_agent": "",
                      "folder": "proj", "agent_pid": 500}
    assert client.get("/api/agent-instances/by-pid?pid=880").json()["instance"] == "claude-code:00aa"
    assert client.get("/api/agent-instances/by-pid?pid=0").status_code == 400
    assert client.get("/api/agent-instances/by-pid?pid=abc").status_code == 400


def test_a_pid_with_no_agent_above_it_or_a_reused_agent_pid_is_not_owned(home, monkeypatch):
    now = time.time()
    monkeypatch.setattr(observe.platform, "process_ancestry",
                        lambda pid, limit: [(pid, 500, now, "sleep 9"), (500, 1, now, "/opt/homebrew/bin/claude -p hi")])
    store.put(store.Instance("claude-code:00bb", "claude-code", "session", now - 3600, now, pid=500))   # started an hour before pid 500
    answer = _client().get("/api/agent-instances/by-pid?pid=901").json()
    assert answer["found"] is False and answer["instance"] == "" and answer["agent_pid"] == 0


def test_a_sub_agent_with_its_own_process_is_named_under_its_session(home, monkeypatch):
    now = time.time()
    monkeypatch.setattr(observe.platform, "process_ancestry",
                        lambda pid, limit: [(pid, 700, now, "ls"), (700, 600, now - 5, "hermes chat"), (600, 1, now - 60, "hermes chat")])
    store.put(store.Instance("hermes:p1", "hermes", "session", now - 30, now, folder="app", pid=600))
    store.put(store.Instance("hermes:p1/c1", "hermes", "sub-agent", now - 4, now, parent="hermes:p1", pid=700))
    owner = owners.of_pid(902)
    assert (owner.instance, owner.sub_agent, owner.folder, owner.pid) == ("hermes:p1", "hermes:p1/c1", "app", 700)
