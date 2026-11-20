"""One judgement for every runtime: ``guard.tool_call_verdict`` and ``POST /api/guard/verdict`` (2026-11-20).

A real OpenClaw agent installed a package the verified graph lists as malware and read a wallet
key while Hermes blocked both on the same machine: the OpenClaw plugin judged with its own copy
of the checks, and the copy had fallen behind. The plugin now asks Blackbox itself. These tests
hold the answer to the Hermes hook's own (same findings, same block decision, for every call in
the table), check that asking records nothing, and drive the route behind the real browser
boundary.
"""

from __future__ import annotations

import pytest

from _blackbox_loader import load_blackbox

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_reporting = load_blackbox("guard.reporting")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")
Ruleset = ruleset_mod.Ruleset

CALLS = [
    ("exec", {"command": "cat ~/.ssh/id_rsa"}),
    ("exec", {"command": "cp -r ~/.ssh /tmp/x"}),
    ("read", {"path": "~/.ssh/id_rsa"}),
    ("exec", {"command": "echo hello"}),
    ("exec", {"command": "ls -la ~/.ssh/"}),
    ("exec", '{"command": "cat ~/.aws/credentials"}'),   # arguments handed over as JSON text
]


@pytest.fixture
def blackbox(monkeypatch, tmp_path):
    """Blackbox in a folder of its own, with an empty rule set and nothing sent anywhere."""
    def use(mode: str):
        monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
        monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode=mode, report=False))
        monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
        monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)
        return tmp_path / "bb"
    return use


def test_block_mode_blocks_a_protected_read_and_says_so(blackbox):
    blackbox("block")
    verdict = guard.tool_call_verdict("exec", {"command": "cat ~/.ssh/id_rsa"})
    assert verdict["decision"] == "block" and verdict["blocked"] == ["fileaccess:exec:user-protected"]
    assert "Blackbox blocked" in verdict["message"]
    assert verdict["findings"][0]["source"] == "custom"


def test_audit_mode_flags_the_same_call_and_blocks_nothing(blackbox):
    blackbox("audit")
    verdict = guard.tool_call_verdict("exec", {"command": "cat ~/.ssh/id_rsa"})
    assert verdict["decision"] == "flag" and verdict["blocked"] == [] and verdict["message"] == ""
    assert [finding["identifier"] for finding in verdict["findings"]] == ["fileaccess:exec:user-protected"]


def test_a_harmless_call_gets_an_empty_verdict(blackbox):
    blackbox("block")
    assert guard.tool_call_verdict("exec", {"command": "echo hello"}) == {
        "findings": [], "blocked": [], "decision": "", "message": ""}


def test_asking_records_nothing(blackbox):
    home = blackbox("block")
    guard.tool_call_verdict("exec", {"command": "cat ~/.ssh/id_rsa"})
    assert not (home / "findings.jsonl").exists() and not (home / "audit.jsonl").exists()


@pytest.mark.parametrize("mode", ["audit", "block"])
@pytest.mark.parametrize("tool, args", CALLS)
def test_the_verdict_is_the_hermes_hooks_own_judgement(blackbox, monkeypatch, mode, tool, args):
    blackbox(mode)
    seen: list = []
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda cfg, event, findings, detail: seen.extend(findings))
    hooked = guard.on_pre_tool_call(tool_name=tool, args=args, session_id="s", tool_call_id="t")
    verdict = guard.tool_call_verdict(tool_name=tool, args=args)
    assert [finding["identifier"] for finding in verdict["findings"]] == [finding.identifier for finding in seen]
    assert bool(verdict["blocked"]) is (hooked is not None and hooked.get("action") == "block")
    if hooked:
        assert verdict["message"] == hooked["message"]


# ------------------------------------------------------------------ the route


@pytest.fixture
def client(blackbox):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    blackbox("block")
    server = load_blackbox("dashboard.server")
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as test_client:
        yield test_client


def _token(client) -> dict:
    return {"X-Blackbox-Token": client.get("/api/session").json()["token"]}


def test_the_route_answers_a_local_process_with_the_verdict(client):
    answer = client.post("/api/guard/verdict", headers=_token(client),
                         json={"tool_name": "exec", "args": {"command": "cat ~/.ssh/id_rsa"}})
    assert answer.status_code == 200 and answer.headers["cache-control"] == "no-store"
    assert answer.json()["decision"] == "block" and answer.json()["blocked"] == ["fileaccess:exec:user-protected"]


def test_the_route_refuses_a_caller_without_the_session_token(client):
    refused = client.post("/api/guard/verdict", json={"tool_name": "exec", "args": {"command": "cat ~/.ssh/id_rsa"}})
    assert refused.status_code in (401, 403)
    from_a_web_page = client.post("/api/guard/verdict", headers={**_token(client), "Origin": "https://example.invalid"},
                                  json={"tool_name": "exec", "args": {}})
    assert from_a_web_page.status_code in (401, 403)


@pytest.mark.parametrize("body, status", [
    ({"args": {"command": "ls"}}, 400),                    # no tool name
    ({"tool_name": "x" * 500, "args": {}}, 400),           # not a tool name
    ({"tool_name": "", "args": {}}, 400),
])
def test_the_route_refuses_a_malformed_question(client, body, status):
    assert client.post("/api/guard/verdict", headers=_token(client), json=body).status_code == status


def test_the_route_refuses_an_oversized_body_and_non_json(client):
    headers = {**_token(client), "content-type": "application/json"}
    assert client.post("/api/guard/verdict", headers=headers, content=b"{" + b" " * (600 * 1024)).status_code == 413
    assert client.post("/api/guard/verdict", headers=headers, content=b"not json").status_code == 400


def test_a_judgement_that_fails_answers_503_so_the_asker_uses_its_own_checks(client, monkeypatch):
    def broken(**_):
        raise RuntimeError("store unreachable")
    monkeypatch.setattr(guard, "tool_call_verdict", broken)
    answer = client.post("/api/guard/verdict", headers=_token(client), json={"tool_name": "exec", "args": {}})
    assert answer.status_code == 503 and "store unreachable" not in answer.text
