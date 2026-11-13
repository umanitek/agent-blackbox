"""Is this node connected to the verified graph, and has its owner approved it? (2026-10-21)

The dashboard's Community card shows one mark for each (the founder asked for a check
mark: a member still waiting for approval has its warnings silently dropped by the
owner). Both come from ONE read of the node's own listing; "approval" is the node's
``callerInvolved`` answer for this agent (DKG 10.0.25: the curator, or an allowlisted
participant), and a missing answer is "could not tell", never "not approved" (LES-011).
"""

from __future__ import annotations

import pytest

from plugins.blackbox import community
from plugins.blackbox.community.membership import join_status
from plugins.blackbox.community.membership.join_status import Admission, JoinState, admission_of
from plugins.blackbox.kernel import identity

OWNER = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70"
GRAPH = f"{OWNER}/agent-blackbox-vm"
MEMBER = "0x" + "60" * 20
CURATED = {"id": GRAPH, "subscribed": True, "accessPolicy": "public", "onChainId": "14",
           "onChain": {"publishPolicy": "curated"}}


@pytest.mark.parametrize(("entry", "address", "admission"), [
    (None, MEMBER, Admission.UNKNOWN),                                      # listing unreadable / not listed
    ({**CURATED, "callerInvolved": True}, OWNER, Admission.OWNER),
    ({**CURATED, "callerInvolved": True}, MEMBER, Admission.APPROVED),
    ({**CURATED, "callerInvolved": False}, MEMBER, Admission.WAITING),
    (CURATED, MEMBER, Admission.UNKNOWN),                                   # the node could not tell
    ({"id": GRAPH, "accessPolicy": "public", "onChainId": "9", "onChain": {"publishPolicy": "open"}}, MEMBER,
     Admission.OPEN),
    ({"id": GRAPH, "accessPolicy": "public", "onChainId": "14"}, MEMBER, Admission.UNKNOWN),   # chain record not in
    ({"id": GRAPH, "accessPolicy": "public"}, MEMBER, Admission.OPEN),     # unregistered P2P graph
    ({"id": GRAPH, "subscribed": True}, MEMBER, Admission.UNKNOWN),        # definition not in yet
])
def test_admission(entry, address, admission):
    assert admission_of(entry, address, GRAPH) is admission


class _Node:
    def __init__(self, rows=None, fail=False):
        self.rows, self.fail, self.listings = rows or [], fail, 0

    def context_graphs(self):
        self.listings += 1
        if self.fail:
            raise OSError("node down")
        return self.rows

    def agent_identity(self):
        return {"agentAddress": MEMBER}


@pytest.fixture(autouse=True)
def _fresh_identity(monkeypatch):
    monkeypatch.setattr(identity, "_reporter_cache", {})


def test_connected_and_approved_come_from_one_listing_read():
    node = _Node([{**CURATED, "callerInvolved": True}])
    status = join_status.read_membership_status(node, GRAPH)
    assert (status.join, status.admission) == (JoinState.JOINED, Admission.APPROVED)
    assert node.listings == 1


def test_an_unreadable_listing_is_unknown_for_both_never_not_approved():
    status = join_status.read_membership_status(_Node(fail=True), GRAPH)
    assert (status.join, status.admission) == (JoinState.UNKNOWN, Admission.UNKNOWN)


@pytest.fixture(autouse=True)
def _fresh_membership_reading():
    """The dashboard caches the node's answer for 30 s; every test starts without it."""
    from plugins.blackbox.dashboard import community_routes

    community_routes.MEMBERSHIP_STATUS.clear()
    yield
    community_routes.MEMBERSHIP_STATUS.clear()


def test_the_community_card_carries_both_marks(monkeypatch):
    from plugins.blackbox.dashboard import community_routes

    monkeypatch.setattr(community, "read_membership_status",
                        lambda client, graph: join_status.MembershipStatus(JoinState.JOINED, Admission.WAITING))
    stats = community_routes.community_stats_payload(lambda cfg: [])
    assert stats["join_state"] == "joined" and stats["admission"] == "waiting"
    assert "waiting for the graph owner's approval" in stats["admission_text"]


# ------------------------------------------------- approved, but not yet allowed to write (2026-10-22)

def _health_inputs(**over):
    from plugins.blackbox.kernel import health

    base = dict(node_reachable=True, ruleset_age_s=60.0, sync_interval_s=300.0, rule_count=10,
                community_configured=True, curator_trusted=True)
    base.update(over)
    return health.HealthInputs(**base)


def _not_admitted(items):
    return [item for item in items if "not admitted" in item.message]


def test_a_waiting_node_that_shares_is_told_its_shares_are_refused():
    from plugins.blackbox.kernel import health

    items = _not_admitted(health.operator_health(_health_inputs(admission="waiting", sharing_enabled=True)))
    assert len(items) == 1
    assert items[0].klass is health.HealthClass.ACTION
    assert "refused" in items[0].what_to_do


def test_a_waiting_node_with_sharing_off_gets_a_note_not_an_alarm():
    from plugins.blackbox.kernel import health

    items = _not_admitted(health.operator_health(_health_inputs(admission="waiting", sharing_enabled=False)))
    assert [item.klass for item in items] == [health.HealthClass.INFO]


@pytest.mark.parametrize("admission", ["approved", "owner", "open", "unknown", ""])
def test_no_banner_unless_the_node_says_waiting(admission):
    """"unknown" is could-not-tell (LES-011): never read as "not admitted"."""
    from plugins.blackbox.kernel import health

    inputs = _health_inputs(admission=admission, sharing_enabled=True)
    assert _not_admitted(health.operator_health(inputs)) == []


def test_the_health_check_reads_admission_from_the_node(monkeypatch):
    from plugins.blackbox.dashboard import community_routes

    monkeypatch.setattr(community, "read_membership_status",
                        lambda client, graph: join_status.MembershipStatus(JoinState.JOINED, Admission.WAITING))
    cfg = type("Cfg", (), {"context_graph_id": GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": ""})()
    assert community_routes._admission_value(cfg) == "waiting"


def test_the_membership_reading_is_shared_for_its_ttl(monkeypatch):
    from plugins.blackbox.dashboard import community_routes

    calls = []
    monkeypatch.setattr(community, "read_membership_status",
                        lambda client, graph: calls.append(graph) or join_status.MembershipStatus(
                            JoinState.JOINED, Admission.APPROVED))
    now = [100.0]
    cache = community_routes.MembershipStatusCache(clock=lambda: now[0])
    cfg = type("Cfg", (), {"context_graph_id": GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": ""})()
    cache.read(cfg)
    cache.read(cfg)
    assert len(calls) == 1
    now[0] += cache.TTL_SECONDS + 1
    cache.read(cfg)
    assert len(calls) == 2


def test_a_failed_share_job_reports_the_nodes_own_reason(monkeypatch):
    """The reason sits at the end of the job record; a 400-character ledger cap used to keep "Can…"."""
    from plugins.blackbox.kernel.dkg_client import DkgClient, DkgError

    job = {"jobId": "j1", "state": "failed", "padding": "x" * 2000,
           "lastError": {"code": "fatal", "message": "no local allowed signing agent key", "retryable": False}}
    client = DkgClient(url="http://127.0.0.1:1")
    monkeypatch.setattr(client, "share_job", lambda job_id: job)
    with pytest.raises(DkgError) as failed:
        client.wait_for_share_job("j1", timeout_s=1, poll_s=0)
    assert str(failed.value) == "SWM share job j1 failed: no local allowed signing agent key"

    monkeypatch.setattr(client, "share_job", lambda job_id: {"state": "failed"})
    with pytest.raises(DkgError, match='failed: {"state": "failed"}'):
        client.wait_for_share_job("j1", timeout_s=1, poll_s=0)


def test_the_dashboard_pops_up_the_same_words_the_health_check_writes():
    """The pop-up keys on the message text; a reworded message must not silently stop it."""
    from pathlib import Path

    from plugins.blackbox.kernel import health

    page = (Path(health.__file__).parents[2] / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    item = health._not_admitted_item(sharing_enabled=True)
    assert 'match: "not admitted to the community graph"' in page
    assert "not admitted to the community graph" in item.message


# --- one join decision: the state machine and the dashboard read the same answer ---------------

_ENTRIES = [
    None,
    {},
    {"accessPolicy": "public"},                                              # unregistered, definition in
    {"accessPolicy": ""},                                                    # unregistered, no definition yet
    {"accessPolicy": "public", "onChain": {}},                               # chain record present but empty
    {"accessPolicy": "public", "onChainId": "7", "onChain": {"publishPolicy": "open"}},
    {"accessPolicy": "public", "onChainId": "7"},                            # registered, policy not in yet
    {"accessPolicy": "private", "callerInvolved": True},
    {"accessPolicy": "private", "callerInvolved": False},
    {"accessPolicy": "private"},                                             # node could not tell
    {"accessPolicy": "public", "onChain": {"publishPolicy": "curated"}, "callerInvolved": False},
]
_SAME_ANSWER = {"member": Admission.APPROVED, "join": Admission.WAITING, "open": Admission.OPEN,
                "undecided": Admission.UNKNOWN}


@pytest.mark.parametrize("entry", _ENTRIES)
def test_the_dashboard_admission_is_the_state_machines_join_decision(entry):
    """The two copies disagreed on a chain record that is present but empty: the state machine
    waited ("undecided") while the dashboard said "open graph". There is one decision now."""
    assert admission_of(entry, "0x" + "ab" * 20, "0x" + "cd" * 20 + "/graph") is (
        Admission.UNKNOWN if entry is None else _SAME_ANSWER[community.membership.join_verdict(entry)])


def test_an_empty_chain_record_is_not_proof_the_graph_is_open():
    assert admission_of({"accessPolicy": "public", "onChain": {}}, "", "g") is Admission.UNKNOWN
