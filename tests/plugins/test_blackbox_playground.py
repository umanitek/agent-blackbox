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


class _SlowNode:
    """A ruleset whose every live read takes 10 s of a fake clock and finds no usable package."""

    verified_scope = SimpleNamespace(verified_counts={"dependency:npm": 100})

    def __init__(self, clock):
        self.clock, self.reads = clock, 0

    def live_browse(self, **_filters):
        self.reads += 1
        self.clock["now"] += 10.0
        return SimpleNamespace(known=True, entries=[{"identifier": "dep:npm:left-pad@*"}])


def test_a_slow_rule_read_refuses_with_the_reason_instead_of_holding_the_request(monkeypatch):
    """Dev node 2026-11-26: "Send: Malware package" sat on "Asking Blackbox… (up to 90 s)" while the
    node was busy. The pick read up to twelve live windows (two node queries each, 10 s timeout
    apiece) with no overall limit, so a slow node held the request for minutes. It now gives up at
    its budget and says why."""
    clock = {"now": 1000.0}
    monkeypatch.setattr(runner, "time", SimpleNamespace(time=lambda: clock["now"], monotonic=lambda: clock["now"]))
    rules = _SlowNode(clock)
    monkeypatch.setattr(runner.ruleset, "get", lambda cfg: rules)
    with pytest.raises(playground.PlaygroundRefused, match="answering slowly"):
        playground.run_test("package", _cfg(report=True, community_sandbox=True))
    assert rules.reads * 10.0 <= runner.RUN_BUDGET_S - runner._SHARE_WAIT_S + 10.0


def test_a_share_still_on_its_way_reads_pending_and_all_shares_share_one_deadline(tmp_path, monkeypatch):
    """Dev node 2026-11-26: a domain test with two findings waited 90 s for the follow-up and 90 s
    per share (~3 min behind a button that said "up to 90 s"), and a share still in flight read as
    "not sent" though the ledger said "accepted" seconds later. The whole wait is now one deadline
    and an unfinished share reads PENDING."""
    import threading
    from plugins.blackbox.guard import reporting

    waits = []
    clock = {"now": 1000.0}   # a join "takes" its whole timeout on this clock, so no real time passes
    monkeypatch.setattr(runner, "time", SimpleNamespace(time=lambda: clock["now"], monotonic=lambda: clock["now"]))

    class Slow(threading.Thread):
        def __init__(self):
            super().__init__(target=release.wait, name="blackbox-community-share", daemon=True)

        def join(self, timeout=None):
            waits.append(timeout)
            clock["now"] += timeout or 0.0

    release = threading.Event()
    shares = [Slow(), Slow()]
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(runner.ruleset, "get", lambda cfg: _Rules())

    def hook(**_kwargs):
        for share in shares:
            share.start()
            reporting._COLLECTED_SHARES.get().append(share)
        audit.record(event="pre_tool_call", findings=[{"identifier": IDENTIFIER, "severity": "high"}], detail={})

    monkeypatch.setattr(runner.guard, "on_pre_tool_call", hook)
    try:
        result = playground.run_test("domain", _cfg(report=True, community_sandbox=True))
    finally:
        release.set()
    assert result.shared == runner.PENDING
    assert len(waits) == 2 and sum(waits) <= runner._SHARE_WAIT_S


def test_the_sharing_tile_reads_the_sandbox_ledger_in_sandbox_mode(tmp_path, monkeypatch):
    """Dev node 2026-11-26: the Threat sharing tile said "on · nothing shared yet" after two accepted
    sandbox shares. In sandbox mode every share is ledgered in the sandbox folder, and the tile read
    only the real ledger. /api/community-stats now carries the sandbox lane's last share too."""
    from plugins.blackbox import community
    from plugins.blackbox.dashboard import community_routes

    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(bb_config, "load_blackbox_config",
                        lambda: _cfg(report=True, community_sandbox=True))
    monkeypatch.setattr(community, "read_membership_status", lambda client, graph: None)
    monkeypatch.setattr(community, "contributing_agent_count", lambda reports: 0)
    community_routes.MEMBERSHIP_STATUS.clear()
    with audit.sandbox_run():
        audit.record_share_outcome(identifier=IDENTIFIER, category="ioc", severity="high", subject="urn:r:1",
                                   asset_name="sandbox-1", ok=True, outcome="accepted")

    stats = community_routes.community_stats_payload(lambda cfg: SimpleNamespace())

    assert stats["sandbox"] is True and stats["last_share"] is None   # the real ledger stays empty
    assert stats["sandbox_last_share"]["identifier"] == IDENTIFIER
    assert stats["sandbox_last_share"]["outcome"] == "accepted"
