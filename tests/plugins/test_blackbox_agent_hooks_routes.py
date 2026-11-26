"""The core dashboard serves coding-agent protection itself (2026-11-21: moved from an add-on
into the public plugin). The paths and JSON are unchanged, so a companion app keeps working on
top of them, and Blackbox alone protects coding agents too."""

from __future__ import annotations

from fastapi.testclient import TestClient

from plugins.blackbox.dashboard import server


def _client() -> TestClient:
    client = TestClient(server.create_app(), base_url="http://127.0.0.1")
    client.headers["X-Blackbox-Token"] = client.get("/api/session").json()["token"]
    return client


def test_the_agent_list_is_served_by_the_core():
    answer = _client().get("/api/agent-hooks")
    assert answer.status_code == 200
    assert {"agents", "kinds"} <= set(answer.json()) and "claude-code" in answer.json()["kinds"]


def test_a_hook_event_is_judged_by_the_core(tmp_path):
    command = f"rm -rf {tmp_path}/hermes/plugins/blackbox"
    answer = _client().post("/api/agent-hooks/event", json={"agent": "claude-code", "event": "pre_tool", "session": "s",
                                                            "cwd": str(tmp_path), "tool_name": "terminal", "args": {"command": command}})
    assert answer.status_code == 200 and answer.json()["decision"] in ("allow", "block")


def test_an_event_without_the_session_token_is_refused():
    client = _client()
    client.headers["X-Blackbox-Token"] = "wrong"
    assert client.post("/api/agent-hooks/event", json={"agent": "claude-code", "event": "stop"}).status_code == 403


def test_a_malformed_event_is_refused():
    assert _client().post("/api/agent-hooks/event", json={"agent": "nobody", "event": "pre_tool"}).status_code == 400
