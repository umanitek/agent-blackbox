"""Community membership: the verified graph's subscription WITH shared memory and its
definition, at most once per process, on the node's word (Refine R0, KI-064/114; one
graph since 2026-10-16).

Before R0 the ruleset subscribed on every refresh. Since the community moved into the
verified graph's shared memory there is no community graph and no join step (the graph
is public), but the owner link stays: an edge that reaches the graph only through relays
gets the graph's definition only from its owner, after a forced catch-up (KI-295, DKG
#3264), and reports reach it over that link (KI-297).
"""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox.community.membership import CommunityMembership
from plugins.blackbox.kernel.dkg_client import DkgError

GRAPH = "0xabc/agent-blackbox-vm-test"
OWNER = "12D3KooWowner"


class _Node:
    def __init__(self, subscribed=False, subscribe_fails=False, running_vm_only=False,
                 defined=True, definition_from_owner=True, peer_id="12D3KooWedge"):
        self.subscribed = subscribed
        self.subscribe_fails = subscribe_fails
        #: a VM-only catch-up job is running: the node hands it back instead of a new one
        self.running_vm_only = running_vm_only
        #: the node holds the graph's definition (its listing names an access policy)
        self.defined = defined
        #: a forced catch-up after dialling the owner brings the definition (DKG #3264)
        self.definition_from_owner = definition_from_owner
        self.peer_id = peer_id
        self.listings = 0
        self.calls = []   # ordered verbs: ("subscribe", graph, shared_memory, forced), ("connect", peer), ("join", ...)

    def status(self):
        return {"peerId": self.peer_id}

    def context_graphs(self):
        self.listings += 1
        row = {"id": GRAPH, "subscribed": self.subscribed, "synced": self.subscribed}
        return [{**row, "accessPolicy": "public"} if self.defined else row]

    def subscribe_context_graph(self, graph, include_shared_memory=True, force_catchup=False):
        self.calls.append(("subscribe", graph, include_shared_memory, force_catchup))
        if self.subscribe_fails:
            raise DkgError("Context Graph read authority is temporarily unavailable")
        self.subscribed = True
        if force_catchup and self.definition_from_owner and ("connect", OWNER) in self.calls:
            self.defined = True
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

    @property
    def dials(self):
        return [call for call in self.calls if call[0] == "connect"]


def _cfg(graph=GRAPH, owner=OWNER):
    return SimpleNamespace(context_graph_id=graph, graph_peer_id=owner)


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_dials_the_owner_then_subscribes_the_verified_graph_with_shared_memory():
    node = _Node()
    ok, _ = CommunityMembership().ensure(node, _cfg())
    assert ok and node.calls == [("connect", OWNER), ("subscribe", GRAPH, True, False)]   # no join (D-040)


def test_a_subscribed_node_without_the_definition_dials_the_owner_and_forces_a_catchup():
    """The listing says subscribed and synced, but names no access policy: every write
    would be refused CONTEXT_GRAPH_NOT_FOUND. Synced is not the signal; the definition is."""
    node = _Node(subscribed=True, defined=False)
    membership = CommunityMembership()
    assert membership.ensure(node, _cfg()) == (True, "subscribed")
    assert node.calls == [("connect", OWNER), ("subscribe", GRAPH, True, True)]
    membership.ensure(node, _cfg())
    assert len(node.subscribes) == 1, "confirmed once the definition is in"


def test_a_definition_still_missing_is_fetched_again_after_the_short_window_not_every_beat():
    clock = _Clock()
    node = _Node(subscribed=True, defined=False, definition_from_owner=False)
    membership = CommunityMembership(clock=clock)
    ok, detail = membership.ensure(node, _cfg())
    assert ok and "definition" in detail   # reads keep working meanwhile
    for _ in range(3):   # the pulse beats every ~20 s
        clock.now += 15
        membership.ensure(node, _cfg())
    assert len(node.subscribes) == 1, "still inside the short window"
    clock.now += CommunityMembership.FAILED_SUBSCRIBE_RETRY_SECONDS
    membership.ensure(node, _cfg())
    assert node.subscribes == [("subscribe", GRAPH, True, True)] * 2
    assert node.calls[-2:] == [("connect", OWNER), ("subscribe", GRAPH, True, True)]   # dial, then force


def test_the_owner_link_is_redialled_every_two_minutes_once_confirmed():
    """KI-297: a node that lost the owner link stayed subscribed while receiving nothing."""
    clock = _Clock()
    node = _Node()
    membership = CommunityMembership(clock=clock)
    membership.ensure(node, _cfg())
    clock.now += CommunityMembership.OWNER_LINK_SECONDS - 1
    membership.ensure(node, _cfg())
    assert len(node.dials) == 1
    clock.now += 2
    membership.ensure(node, _cfg())
    assert len(node.dials) == 2 and len(node.subscribes) == 1


def test_the_owners_own_node_never_dials_itself():
    node = _Node(peer_id=OWNER)
    membership = CommunityMembership()
    assert membership.ensure(node, _cfg()) == (True, "subscribed")
    assert node.calls == [("subscribe", GRAPH, True, False)]


def test_without_an_owner_peer_nothing_is_dialled_or_waited_for():
    node = _Node(defined=False)
    membership = CommunityMembership()
    assert membership.ensure(node, _cfg(owner="")) == (True, "subscribed")
    assert node.calls == [("subscribe", GRAPH, True, False)]


def test_a_node_subscribed_without_shared_memory_is_asked_once_to_add_it():
    """A node an older release subscribed VM-only lists the graph as subscribed; the
    listing alone must not stop the one subscribe that adds the shared memory."""
    node = _Node(subscribed=True)
    membership = CommunityMembership()
    for _ in range(20):
        membership.ensure(node, _cfg())
    assert node.subscribes == [("subscribe", GRAPH, True, False)]


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
    """The pulse calls ensure() every ~20 s: once the subscription and the definition
    are confirmed the node's listing is re-read once per RETRY_SECONDS, and nothing is
    re-subscribed."""
    clock = _Clock()
    node = _Node()
    membership = CommunityMembership(clock=clock)
    membership.ensure(node, _cfg())
    confirmed_at = node.listings
    for _ in range(4):
        membership.ensure(node, _cfg())
    assert node.listings == confirmed_at and len(node.subscribes) == 1
    clock.now += CommunityMembership.RETRY_SECONDS + 1
    membership.ensure(node, _cfg())
    membership.ensure(node, _cfg())
    assert node.listings == confirmed_at + 1 and len(node.subscribes) == 1


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
    node.subscribe_context_graph = lambda graph, include_shared_memory=True, force_catchup=False: {"subscribed": graph}
    membership = CommunityMembership()
    assert membership.ensure(node, _cfg()) == (True, "subscribed")
    assert membership.ensure(node, _cfg()) == (True, "subscribed")


def test_no_graph_configured_does_nothing():
    node = _Node()
    ok, _detail = CommunityMembership().ensure(node, _cfg(graph=""))
    assert not ok and node.calls == []
