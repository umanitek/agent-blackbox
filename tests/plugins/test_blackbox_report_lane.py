"""Community statements are written into the community sub-graph (2026-10-12).

DKG 10.0.23 refuses members' direct shares into a catalog-mode graph's root, so
every community statement goes into a named sub-graph. The graph's OWNER
registers it (``community.ensure_report_lane``, once per process per graph,
before its first write); every other node writes into the owner's sub-graph
as it is, because DKG 10.0.25 looks the owner's registration up at a member's
first write (OriginTrail/dkg#3306).
"""

from __future__ import annotations

import pytest

from plugins.blackbox.community.membership import CommunityMembership
from plugins.blackbox.kernel import constants, identity
from plugins.blackbox.kernel.dkg_client import DkgError

OWNER = "0x00000000000000000000000000000000000000aa"
GRAPH = f"{OWNER}/agent-blackbox-vm"


@pytest.fixture(autouse=True)
def _fresh_identity(monkeypatch):
    monkeypatch.setattr(identity, "_reporter_cache", {})


class _Node:
    def __init__(self, address: str = OWNER, fail_with: str = "") -> None:
        self.address = address
        self.calls = []
        self.fail_with = fail_with

    def agent_identity(self):
        if not self.address:
            raise DkgError("node starting")
        return {"agentAddress": self.address}

    def request(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        if self.fail_with:
            raise DkgError(self.fail_with, status_code=400)
        return {"created": body["subGraphName"]}


def test_the_owners_node_registers_the_lane_once_per_graph():
    node, membership = _Node(), CommunityMembership()
    assert membership.ensure_report_lane(node, GRAPH) and membership.ensure_report_lane(node, GRAPH)
    assert node.calls == [("POST", "/api/sub-graph/create",
                           {"contextGraphId": GRAPH, "subGraphName": constants.COMMUNITY_SUB_GRAPH})]
    membership.ensure_report_lane(node, "0x00000000000000000000000000000000000000AA/other")
    assert len(node.calls) == 2                                   # a second graph of its own, address in any case


def test_a_member_registers_nothing_and_writes_into_the_owners_sub_graph():
    node, membership = _Node(address="0x00000000000000000000000000000000000000bb"), CommunityMembership()
    assert membership.ensure_report_lane(node, GRAPH) is True
    assert membership.ensure_report_lane(node, "agent-blackbox-vm-test") is True   # an id with no owner part
    assert node.calls == []


def test_an_already_registered_lane_counts_as_ready():
    node, membership = _Node(fail_with='Sub-graph "reports" already exists'), CommunityMembership()
    assert membership.ensure_report_lane(node, GRAPH) is True
    node.fail_with = ""
    membership.ensure_report_lane(node, GRAPH)
    assert len(node.calls) == 1                                                     # remembered as ready


def test_a_failed_registration_is_logged_and_tried_again(caplog):
    node, membership = _Node(fail_with="context graph not found"), CommunityMembership()
    assert membership.ensure_report_lane(node, GRAPH) is False
    assert "could not register the community subgraph" in caplog.text
    node.fail_with = ""
    assert membership.ensure_report_lane(node, GRAPH) is True and len(node.calls) == 2


def test_an_unknown_own_address_registers_nothing_yet_and_asks_again():
    node, membership = _Node(address=""), CommunityMembership()
    assert membership.ensure_report_lane(node, GRAPH) is False and node.calls == []
    node.address = OWNER
    assert membership.ensure_report_lane(node, GRAPH) is True and len(node.calls) == 1


@pytest.mark.parametrize("module_path", ["plugins/blackbox/community/sharing.py",
                                         "plugins/blackbox/curate/publishing/publish.py",
                                         "plugins/blackbox/curate/upkeep/published.py"])
def test_every_community_writer_registers_the_lane_before_sharing(module_path):
    """Every call of share_knowledge_asset is preceded by the lane registration."""
    from pathlib import Path
    lines = Path(module_path).read_text(encoding="utf-8").splitlines()
    shares = [i for i, line in enumerate(lines) if "share_knowledge_asset(" in line]
    assert shares
    for i in shares:
        assert "ensure_report_lane(" in lines[i - 1], f"{module_path}:{i + 1}"
