"""The Playground (2026-10-21): sandbox tests run only in sandbox mode, stay out of the
real logs, and the dashboard says plainly why a test cannot run.

The real network path (share into the sandbox lane, other members receive it) is
proven on the bench; these tests pin the local contract around it.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from plugins.blackbox import audit, playground
from plugins.blackbox.dashboard import playground_routes
from plugins.blackbox.kernel import config as bb_config
from plugins.blackbox.kernel import constants, settings
from plugins.blackbox.playground import runner

IDENTIFIER = "ioc:domain:listed-phish.example"


def _cfg(**overrides):
    return dataclasses.replace(bb_config.BlackboxConfig(), context_graph_id="0xabc/graph", **overrides)


def test_a_test_refuses_while_sandbox_mode_is_off():
    with pytest.raises(playground.PlaygroundRefused, match="Sandbox mode is off"):
        playground.run_test("domain", _cfg(report=True, community_sandbox=False))


def test_a_test_refuses_while_sharing_is_off():
    with pytest.raises(playground.PlaygroundRefused, match="Community sharing is off"):
        playground.run_test("domain", _cfg(report=False, community_sandbox=True))


def test_an_unknown_kind_is_refused_by_name():
    with pytest.raises(playground.PlaygroundRefused, match="Unknown test kind"):
        playground.run_test("seed-phrase", _cfg(report=True, community_sandbox=True))


class _Rules:
    """A ruleset holding one listed domain."""

    verified_scope = SimpleNamespace(verified_counts={"ioc": 1})

    def live_browse(self, **_filters):
        return SimpleNamespace(known=True, entries=[{"identifier": IDENTIFIER}])

    def ioc_rules(self, identifiers):
        return SimpleNamespace(rules={IDENTIFIER: {"severity": "high"}})


def test_a_test_runs_the_real_hook_inside_the_sandbox_and_keeps_the_real_logs_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(runner.ruleset, "get", lambda cfg: _Rules())
    calls = []

    def hook(**kwargs):
        calls.append((kwargs["tool_name"], kwargs["args"], kwargs["session_id"], audit.in_sandbox_run()))
        audit.record(event="pre_tool_call", findings=[{"identifier": IDENTIFIER, "severity": "high"}], detail={})

    monkeypatch.setattr(runner.guard, "on_pre_tool_call", hook)
    result = playground.run_test("domain", _cfg(report=True, community_sandbox=True))
    assert calls == [("web_fetch", {"url": "https://listed-phish.example/"}, runner.SESSION_ID, True)]
    assert result.identifier == IDENTIFIER and result.decision == "flagged"
    assert (tmp_path / "sandbox" / "findings.jsonl").exists()
    assert not (tmp_path / "findings.jsonl").exists()
    assert [row.get("identifier") for row in playground.recent_tests()] == [IDENTIFIER]


def test_the_route_answers_409_with_the_reason(monkeypatch):
    def refuse(kind):
        raise playground.PlaygroundRefused("Sandbox mode is off. Turn it on under Community sharing to run tests.")

    monkeypatch.setattr(playground, "run_test", refuse)
    status, body = playground_routes.run_payload({"kind": "domain"})
    assert status == 409 and body == {"ok": False, "error": "Sandbox mode is off. Turn it on under Community sharing to run tests."}


def test_the_state_reads_no_lane_outside_sandbox_mode(monkeypatch):
    monkeypatch.setattr(bb_config, "load_blackbox_config", lambda: _cfg(community_sandbox=False))
    monkeypatch.setattr(playground, "read_lane", lambda cfg: pytest.fail("the lane is read only in sandbox mode"))
    state = playground_routes.state_payload()
    assert state["sandbox"] is False and state["tests"] == [] and state["lane"]["entries"] == []


def test_sandbox_mode_is_a_validated_setting():
    updates, errors = settings._validate({"community_sandbox": True})
    assert updates == {"community_sandbox": True} and errors == []
    _, errors = settings._validate({"community_sandbox": "yes"})
    assert errors == ["community_sandbox must be a boolean"]


def test_the_lane_view_counts_distinct_reporters():
    entries = (playground.LaneEntry("a", "0xAA", "high", True), playground.LaneEntry("b", "0xaa", "high", True),
               playground.LaneEntry("c", "0xbb", "high", False))
    assert playground.LaneView("g", True, entries).agents == 2


def test_the_lane_reader_asks_for_the_sandbox_lane_only():
    asked = {}

    class _Client:
        def query(self, sparql, graph, view=None, on_error=None, sub_graph="reports"):
            asked.update(graph=graph, view=view, sub_graph=sub_graph, limited="LIMIT" in sparql)
            guardian = "http://umanitek.ai/ontology/guardian/"
            return [{"r": "urn:guardian:report:a:1", "p": guardian + key, "o": value}
                    for key, value in (("identifier", IDENTIFIER), ("reporter", "0xAA"), ("severity", "high"))]

        def request(self, *args, **kwargs):
            return {}

    view = playground.read_lane(_cfg(), client=_Client())
    assert asked == {"graph": "0xabc/graph", "view": constants.VIEW_SHARED_WORKING_MEMORY, "sub_graph": "sandbox",
                     "limited": True}
    assert view.readable and view.entries[0].identifier == IDENTIFIER


def test_the_run_route_takes_a_json_body_and_answers_409(monkeypatch):
    """Drive the REAL route (not the handler): the first bench run found the body
    declared in a way FastAPI read as a required query parameter (422)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    def refuse(kind):
        raise playground.PlaygroundRefused(f"refused {kind}")

    monkeypatch.setattr(playground, "run_test", refuse)
    app = FastAPI()
    playground_routes.register(app, lambda key, producer, default, ttl=None: producer())
    reply = TestClient(app).post("/api/playground/run", json={"kind": "domain"})
    assert reply.status_code == 409 and reply.json() == {"ok": False, "error": "refused domain"}
    assert TestClient(app).get("/playground.js").status_code == 200


def test_a_test_waits_for_its_own_share_only_never_another_agents(tmp_path, monkeypatch):
    """run_test joined every live thread NAMED "blackbox-community-share" — a literal copied from
    community/sharing.py — so it also waited (up to 90 s each) on real agents' shares running at
    the same time, and a renamed thread would have made the wait a silent no-op. It now waits for
    the shares started inside its own run (guard.collecting_shares)."""
    import threading
    from plugins.blackbox.guard import reporting

    class Recorded(threading.Thread):
        def __init__(self, name):
            super().__init__(target=release.wait, name=name, daemon=True)
            self.joined = False

        def join(self, timeout=None):
            self.joined = True
            return super().join(0.05)

    release = threading.Event()
    other_agents = Recorded("blackbox-community-share")
    other_agents.start()
    own = Recorded("blackbox-community-share")
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(runner.ruleset, "get", lambda cfg: _Rules())

    def hook(**_kwargs):
        own.start()
        reporting._COLLECTED_SHARES.get().append(own)   # what the share hand-off does for a share it starts
        audit.record(event="pre_tool_call", findings=[{"identifier": IDENTIFIER, "severity": "high"}], detail={})

    monkeypatch.setattr(runner.guard, "on_pre_tool_call", hook)
    try:
        playground.run_test("domain", _cfg(report=True, community_sandbox=True))
        assert own.joined and not other_agents.joined
    finally:
        release.set()
