"""Community membership: the verified graph's subscription WITH shared memory, at most
once per process, on the node's word (Refine R0, KI-064/114; one graph since 2026-10-16).

Before R0 the ruleset subscribed on every refresh. Since the community moved into the
verified graph's shared memory there is no community graph, no owner peer to dial and no
join step (the graph is registered on chain, and public).
"""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox.community.membership import CommunityMembership
from plugins.blackbox.kernel.dkg_client import DkgError

GRAPH = "0xabc/agent-blackbox-vm-test"


class _Node:
    def __init__(self, subscribed=False, subscribe_fails=False, running_vm_only=False):
        self.subscribed = subscribed
        self.subscribe_fails = subscribe_fails
        #: a VM-only catch-up job is running: the node hands it back instead of a new one
        self.running_vm_only = running_vm_only
        self.listings = 0
        self.calls = []   # ordered verbs: ("subscribe", graph, include_shared_memory), ("connect", ...), ("join", ...)

    def context_graphs(self):
        self.listings += 1
        return [{"id": GRAPH, "subscribed": self.subscribed, "synced": self.subscribed, "accessPolicy": "public"}]

    def subscribe_context_graph(self, graph, include_shared_memory=True):
        self.calls.append(("subscribe", graph, include_shared_memory))
        if self.subscribe_fails:
            raise DkgError("Context Graph read authority is temporarily unavailable")
        self.subscribed = True
        return {"subscribed": graph,
                "catchup": {"status": "running" if self.running_vm_only else "queued",
                            "includeWorkspace": not self.running_vm_only, "jobId": "job-1"}}

    def connect_peer(self, peer):
        self.calls.append(("connect", peer))

    def request_join(self, graph, peer):
        self.calls.append(("join", peer))

    @property
    def subscribes(self):
        return [call for call in self.calls if call[0] == "subscribe"]


def _cfg(graph=GRAPH):
    return SimpleNamespace(context_graph_id=graph)


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_subscribes_the_verified_graph_with_shared_memory_and_nothing_else():
    node = _Node()
    ok, _ = CommunityMembership().ensure(node, _cfg())
    assert ok and node.calls == [("subscribe", GRAPH, True)]   # no owner dial, no join (D-040)


def test_a_node_subscribed_without_shared_memory_is_asked_once_to_add_it():
    """A node an older release subscribed VM-only lists the graph as subscribed; the
    listing alone must not stop the one subscribe that adds the shared memory."""
    node = _Node(subscribed=True)
    membership = CommunityMembership()
    for _ in range(20):
        membership.ensure(node, _cfg())
    assert node.subscribes == [("subscribe", GRAPH, True)]


def test_a_running_vm_only_catchup_is_asked_again_a_minute_later():
    """The node hands back a VM-only job that is still running: shared memory is not
    in yet, so the subscribe is repeated after the short window until it is."""
    clock = _Clock()
    node = _Node(subscribed=True, running_vm_only=True)
    membership = CommunityMembership(clock=clock)
    ok, detail = membership.ensure(node, _cfg())
    assert ok and "shared memory" in detail
    clock.now += CommunityMembership.FAILED_SUBSCRIBE_RETRY_SECONDS - 1
    membership.ensure(node, _cfg())
    assert len(node.subscribes) == 1, "still inside the short window"
    clock.now += 2
    node.running_vm_only = False   # the VM job ended: the node starts one with shared memory
    membership.ensure(node, _cfg())
    clock.now += CommunityMembership.FAILED_SUBSCRIBE_RETRY_SECONDS + 1
    membership.ensure(node, _cfg())
    assert len(node.subscribes) == 2, "confirmed once the answer covers shared memory"


def test_once_confirmed_only_the_listing_is_read_and_only_after_the_window():
    """The pulse calls ensure() every ~20 s: after the shared-memory subscribe the
    node's listing is re-read once per RETRY_SECONDS, and nothing is re-subscribed."""
    clock = _Clock()
    node = _Node()
    membership = CommunityMembership(clock=clock)
    for _ in range(5):
        membership.ensure(node, _cfg())
    assert node.listings == 0 and len(node.subscribes) == 1
    clock.now += CommunityMembership.RETRY_SECONDS + 1
    membership.ensure(node, _cfg())
    membership.ensure(node, _cfg())
    assert node.listings == 1 and len(node.subscribes) == 1


def test_a_node_that_lost_the_subscription_is_subscribed_again():
    clock = _Clock()
    node = _Node()
    membership = CommunityMembership(clock=clock)
    membership.ensure(node, _cfg())
    node.subscribed = False   # e.g. an operator unsubscribed it
    clock.now += CommunityMembership.RETRY_SECONDS + 1
    membership.ensure(node, _cfg())
    assert len(node.subscribes) == 2


def test_a_refused_subscribe_is_retried_after_the_short_window_not_the_long_one():
    clock = _Clock()
    node = _Node(subscribe_fails=True)
    membership = CommunityMembership(clock=clock)
    assert membership.ensure(node, _cfg())[0] is False
    clock.now += CommunityMembership.FAILED_SUBSCRIBE_RETRY_SECONDS - 1
    membership.ensure(node, _cfg())
    assert len(node.subscribes) == 1, "still inside the short window"
    clock.now += 2
    membership.ensure(node, _cfg())
    assert len(node.subscribes) == 2, "retried after the short window, long before RETRY_SECONDS"


def test_an_answer_that_does_not_name_its_catchup_counts_as_covering_shared_memory():
    """Older nodes answer a subscribe without the catch-up block: the request asked
    for shared memory, so the subscription is taken as confirmed."""
    node = _Node()
    node.subscribe_context_graph = lambda graph, include_shared_memory=True: {"subscribed": graph}
    membership = CommunityMembership()
    assert membership.ensure(node, _cfg()) == (True, "subscribed")
    assert membership.ensure(node, _cfg()) == (True, "subscribed")


def test_no_graph_configured_does_nothing():
    node = _Node()
    ok, _detail = CommunityMembership().ensure(node, _cfg(graph=""))
    assert not ok and node.calls == []
