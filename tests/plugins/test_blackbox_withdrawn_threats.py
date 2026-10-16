"""KI-275 — a threat that was rejected, revoked or retracted is never kept on a reader.

Readers keep a counted threat whose network copies expired for up to 90 days
(R5), and keep their last good tier through an empty read they do not believe
yet (KI-262) or a pause. A rejection or a retraction also makes a threat
vanish from the read — on purpose. Before this fix both safety nets brought
the threat back at its old FLAG, so a curator rejection did not reach the hot
path for up to 90 days. Reductions always get through (LES-016).

The curators here are the verified authority's (one graph, 2026-10-16): its
listing, pause and revocation in Verified Memory, its rejection in the shared
memory beside the reports.
"""

from __future__ import annotations

from datetime import date

import pytest
from _community_rows import GRAPH, NETWORK, Reporter
from _machines import SWM, VM, Machine, Network, share_report
from test_blackbox_authority import TODAY, Side
from test_blackbox_curator_view import _entry

from plugins.blackbox.community import CommunityRead, ReadState, report_builder
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.authority import Authority, home_graph
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)
X, Y = "ioc:ip:203.0.113.7", "ioc:ip:203.0.113.8"


@pytest.fixture(autouse=True)
def no_join(monkeypatch):
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


class Reader:
    """The verified curators (their root trusted, their manifest and a listing of reporter F in
    Verified Memory), F's reports in the shared memory, and a reader that keeps its own tier
    history, on one in-memory network."""

    def __init__(self, tmp_path, monkeypatch):
        self.net = Network()
        self.reader = Machine(self.net, tmp_path, monkeypatch, "R")
        self.curators = Side(GRAPH)
        monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", self.curators.root_hex)
        self.net.put(GRAPH, VM, "U", "key-manifest-1-1",
                     cs.manifest_quads(km.sign_manifest(self.curators.manifest, self.curators.root)))
        self.f = Reporter("0xf")
        self.say(Kind.COUNTED_AUTHORS, f"author:{self.f.author}", _entry(self.f.author))
        self.tier = None

    def say(self, kind, identifier, fields):
        """Two curators sign *kind*, published where it lives: an enforcement statement in
        Verified Memory, an advisory one in the shared memory."""
        envelope = cs.sign_statement(kind, identifier, sequence=1, fields=fields, key=self.curators.curators[0],
                                     manifest=self.curators.manifest, graph=GRAPH, day=date.fromisoformat(TODAY))
        envelope = signing.cosign(envelope, self.curators.curators[1])
        memory = VM if home_graph(Authority.VERIFIED, kind) == "verified" else SWM
        self.net.put(GRAPH, memory, "U", f"curator-{kind.value}-{identifier}", cs.statement_quads(envelope))

    def compile(self):
        with self.reader:
            tier = compiler.Ruleset()
            community_tier.apply_community_tier(tier, self.reader.node, CFG, self.tier)
        self.tier = tier
        return tier

    def report(self, identifier):
        share_report(self.reader.node, identifier, self.f)

    def retract(self, identifier):
        signer = ReportSigner(private_key=self.f.key, environment=NETWORK, graph=GRAPH)
        self.net.put(GRAPH, SWM, "F", f"retract-{identifier}",
                     report_builder.build_retraction_quads(identifier=identifier, reporter_address=self.f.address, signer=signer))

    def expire(self, identifier):
        """Shared memory forgot this threat's report (no statement says anything about it)."""
        store = self.net.assets[(GRAPH, SWM)]
        def is_its_report(quads):
            return (any(q["object"].rstrip(">").endswith("ThreatReport") for q in quads)
                    and any(identifier in q["object"] for q in quads))
        for key in [key for key, quads in store.items() if is_its_report(quads)]:
            del store[key]

    def matchable(self, identifier):
        return identifier in self.tier.ioc


@pytest.fixture
def team(tmp_path, monkeypatch):
    return Reader(tmp_path, monkeypatch)


def test_a_rejected_threat_is_gone_at_once_while_others_stay(team):
    team.report(X), team.report(Y)
    assert team.compile() and team.matchable(X) and team.matchable(Y)
    team.say(Kind.REJECTION, X, {"reason": "benign"})
    team.compile()
    assert X not in team.tier.community and not team.matchable(X) and team.matchable(Y)
    team.compile()                                                           # and on every later read
    assert X not in team.tier.community


def test_a_retracted_threat_is_not_kept_locally(team):
    team.report(X), team.report(Y)
    team.compile()
    team.retract(X)
    team.compile()
    assert X not in team.tier.community and not team.matchable(X) and team.matchable(Y)


def test_when_every_missing_threat_was_withdrawn_nothing_is_kept(team):
    team.report(X)
    team.compile()
    team.say(Kind.REJECTION, X, {"reason": "benign"})
    tier = team.compile()
    assert tier.community == {} and not team.matchable(X)


def test_a_rejection_published_after_the_reports_expired_is_still_seen(team):
    """The reader asks the curators about every threat it holds, not only those still reported."""
    team.report(X), team.report(Y)
    team.compile()
    team.say(Kind.REJECTION, X, {"reason": "benign"})
    team.expire(X)                                                           # X's report is gone; Y's is still there
    team.compile()
    assert X not in team.tier.community and not team.matchable(X) and team.matchable(Y)


def test_an_empty_read_keeps_what_it_cannot_explain_and_drops_what_it_can(team):
    team.report(X), team.report(Y)
    team.compile()
    team.expire(Y)                                                           # Y vanished for no stated reason
    team.say(Kind.REJECTION, X, {"reason": "benign"})                    # X was rejected
    team.expire(X)                                                           # and its report is gone too: the read is empty
    team.compile()
    assert X not in team.tier.community and not team.matchable(X)
    assert team.matchable(Y) and Y in team.tier.community                    # a busy store must not wipe Y (KI-262)


def test_a_threat_that_merely_expired_is_still_kept_locally(team):
    team.report(X), team.report(Y)
    team.compile()
    team.expire(X)
    team.compile()
    assert team.tier.community[X]["networkLive"] == "no" and team.matchable(X)


def test_a_rejection_gets_through_while_intake_is_paused(team):
    team.report(X), team.report(Y)
    team.compile()
    team.say(Kind.PAUSE, "curator", {"until": "2026-10-05"})                # three days from TODAY
    team.say(Kind.REJECTION, X, {"reason": "benign"})
    tier = team.compile()
    assert tier.community_paused and X not in tier.community and not team.matchable(X) and team.matchable(Y)


def test_a_revocation_counts_as_withdrawn():
    revoked = CuratorRecord(kind=Kind.REVOCATION, identifier=X, sequence=2, day="2026-10-03",
                            fields=(("reason", "false-positive"),), signers=frozenset({"a" * 64, "b" * 64}))
    rejected = CuratorRecord(kind=Kind.REJECTION, identifier=Y, sequence=2, day="2026-10-03",
                             fields=(("reason", "benign"),), signers=frozenset({"a" * 64, "b" * 64}))
    read = CommunityRead(ReadState.ROWS, curator=cv.CuratorView(verdicts={X: revoked, Y: rejected}))
    assert community_tier._withdrawn(read) == {X, Y}
