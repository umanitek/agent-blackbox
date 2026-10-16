"""Community-graph statistics count verified signers (Refine R0d).

The dashboard's community numbers — contributing agents, the "Community graph
— connected agents" section, the most-reported board — and
`blackbox report --status` all read through ONE verified reader and count by
signer key, never by the self-described reporter field (KI-067/110). History:
community agents got their own dashboard section on 2026-10-01 (FIX-0018).
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import attach, audit
from plugins.blackbox.community import graph_stats
from plugins.blackbox.community.verification import VerifiedReport
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import dkg_client, reporter_key

from _community_rows import GRAPH, NETWORK, Reporter, signed_row

LOCAL_ADDRESS = "0xAAAA000000000000000000000000000000000001"


def _report(identifier, author, reporter="0x3280c57e351eed219fa17963036daa3653eea6c6", severity="high", framework="hermes"):
    return VerifiedReport(subject=f"urn:guardian:report:{reporter}:{author}:{identifier}", identifier=identifier,
                          author=author, reporter=reporter, severity=severity, framework=framework)


# ----------------------------------------------------------- pure functions


def test_contributing_agents_are_distinct_signers():
    reports = [_report("ioc:a", "k1", "0xf79e09c14d5c229b89c4ac719117cf2bd56fe5f1"), _report("ioc:b", "k1", "0x680964861de62daa6c399f0d8887109f83e17cff"), _report("ioc:a", "k2", "0x9be41e857974f2c946bef18de599f34e5ac1d5fe")]
    assert graph_stats.contributing_agent_count(reports) == 2


def test_community_agents_group_by_signer_and_flag_self():
    reports = [_report("ioc:a", "k1", "0x476fe637b32b228e4d914d84df1ead392b85b91f", framework="hermes"), _report("ioc:b", "k1", "0x476fe637b32b228e4d914d84df1ead392b85b91f", framework="openclaw"),
               _report("ioc:a", "k2", "0xc8751cdc536e5bfd83df653251b571c3e61f6096")]
    agents = graph_stats.community_agents(reports, own_author="k1")
    assert [a["author"] for a in agents] == ["k1", "k2"]          # this node first
    assert agents[0]["is_self"] and agents[0]["reports"] == 2
    assert agents[0]["frameworks"] == ["hermes", "openclaw"]
    assert not agents[1]["is_self"]


def test_one_signer_claiming_many_addresses_is_one_agent():
    reports = [_report(f"ioc:{i}", "k1", f"0xpose{i}") for i in range(5)]
    agents = graph_stats.community_agents(reports)
    assert len(agents) == 1 and agents[0]["reports"] == 5


def test_most_reported_ranks_by_distinct_signers_and_keeps_max_severity():
    reports = [_report("ioc:a", "k1", severity="low"), _report("ioc:a", "k2", severity="critical"),
               _report("ioc:b", "k1"), _report("ioc:b", "k1")]
    board = graph_stats.most_reported_threats(reports, limit=5)
    assert board[0] == {"identifier": "ioc:a", "reporters": 2, "severity": "critical",
                        "matched_by": [], "blackbox_versions": []}   # pre-§03.6 reports state neither
    assert board[1]["reporters"] == 1


def test_reports_signed_by_counts_only_that_signer():
    reports = [_report("ioc:a", "k1"), _report("ioc:b", "k1"), _report("ioc:a", "k2")]
    assert graph_stats.reports_signed_by(reports, "k1") == 2
    assert graph_stats.reports_signed_by(reports, "") == 0


# -------------------------------------------------------------- endpoints


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Dashboard over a fake node serving REAL signed rows: this node (own key)
    plus one remote node posing as three addresses with one key."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setenv("BLACKBOX_CONTEXT_GRAPH_ID", GRAPH)   # the community lives in this graph (one graph since 2026-10-16)
    own = Reporter(LOCAL_ADDRESS, reporter_key.ReporterKeyStore().load_or_create())
    poser = Reporter("0x2bf0e3c192ac5aa603813050094d4e394a7ae78d").key
    rows = [signed_row("ioc:domain:evil.example", own), signed_row("ioc:domain:mine.example", own)]
    rows += [signed_row("ioc:domain:evil.example", Reporter(f"0xpose{i}", poser)) for i in range(3)]
    unsigned = signed_row("ioc:domain:unsigned.example", Reporter("0xd6270b3dd99e247cdd76538296c0a24a6ba98248"))
    del unsigned["signedStatement"]
    rows.append(unsigned)

    def query(self, sparql, graph, view=None, on_error=None, **kw):
        if "ThreatReport" in sparql and "FILTER(STR(?r)" not in sparql:
            return rows
        return []

    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: True)
    monkeypatch.setattr(dkg_client.DkgClient, "status", lambda self, timeout=None: {"networkId": NETWORK})
    monkeypatch.setattr(dkg_client.DkgClient, "agent_identity", lambda self: {"agentAddress": LOCAL_ADDRESS})
    monkeypatch.setattr(dkg_client.DkgClient, "query", query)
    monkeypatch.setattr(audit, "local_active_frameworks", lambda: ["hermes"])
    monkeypatch.setattr(attach, "attach_all", lambda **kwargs: {"hermes": [], "openclaw": []})
    with TestClient(server.create_app(), base_url="http://127.0.0.1") as client:
        yield client


def _once_loaded(client, path, ready):
    """Community data loads off the request path (stale-while-revalidate)."""
    deadline = time.monotonic() + 5
    while True:
        body = client.get(path).json()
        if ready(body):
            return body
        assert time.monotonic() < deadline, f"never loaded: {body}"
        time.sleep(0.05)


def test_community_agents_section_counts_signers(wired):
    body = _once_loaded(wired, "/api/agents", lambda b: len(b["community_agents"]) >= 2)
    agents = body["community_agents"]
    assert len(agents) == 2                                     # own key + ONE poser; unsigned dropped
    assert agents[0]["is_self"] and agents[0]["reports"] == 2
    assert agents[1]["reports"] == 3 and not agents[1]["is_self"]


def test_remote_reporters_are_not_connected_agents(wired):
    body = _once_loaded(wired, "/api/agents", lambda b: len(b["community_agents"]) >= 2)
    assert all(row.get("is_local") for row in body["agents"])


def test_contributing_agents_are_verified_signers(wired):
    stats = _once_loaded(wired, "/api/community-stats", lambda b: b["contributing_agents"])
    assert stats["contributing_agents"] == 2


def test_most_reported_board_counts_the_poser_once(wired):
    board = _once_loaded(wired, "/api/reports", lambda b: b["reports"])["reports"]
    evil = next(row for row in board if row["identifier"] == "ioc:domain:evil.example")
    assert evil["reporters"] == 2                                # own + poser — not 4
    assert "ioc:domain:unsigned.example" not in {row["identifier"] for row in board}
