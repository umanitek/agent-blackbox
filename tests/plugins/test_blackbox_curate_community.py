"""Community Curation C4 — curators publish to the graph, honestly.

Three curator machines and a reader over one shared in-memory network
(``_machines``). "Published" means the statement was read back from the graph,
not that the node said yes.

One graph (2026-10-16): there are no community curators for now (the project
lead's decision), so the community authority is dormant and the team here is
the VERIFIED curators (:class:`Curators`): their manifest and enforcement
statements (a trusted-reporter listing among them) go to the graph's Verified
Memory, their advisory statements (verdicts, attestations, heartbeats) to its
shared memory. What the dormant authority may still do — nothing — is tested
with a team that publishes no manifest.
"""

from __future__ import annotations

import dataclasses
import time
from datetime import date

import pytest
from _community_rows import GRAPH, NETWORK, Reporter
from _machines import SWM, VM, Machine, Network, Node

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import consent, context, keys, publishing, transport, verbs
from plugins.blackbox.curate.context import CurateContext
from plugins.blackbox.curate.proposal import ProposalState, ProposalStore
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest
from plugins.blackbox.kernel.signing.authority import Authority
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

VM_GRAPH = GRAPH   # one graph (2026-10-16): the community lives in the verified graph's shared memory
CFG = BlackboxConfig(report=True, context_graph_id=VM_GRAPH)
THREAT = "ioc:ip:203.0.113.7"
ADDRESS = "0x" + "a" * 40
EVIDENCE = "advisory:MAL-2026-0001"
#: Where the verified authority's promotions are published from (its manifest names it).
PROMOTION_AUTHOR = "0x" + "1" * 40


class Curators:
    """Three curator machines (A, B, C) and a reader (R) on one network: the
    VERIFIED authority's root held on A and, unless *publish_manifest* is
    False, its 2-of-3 key manifest published in the graph's Verified Memory. A
    community root is configured too, so a test can show the dormant community
    authority acts for nobody."""

    def __init__(self, tmp_path, monkeypatch, *, publish_manifest=True):
        self.net = Network()
        self.monkeypatch = monkeypatch
        self.a, self.b, self.c, self.reader = (Machine(self.net, tmp_path, monkeypatch, name) for name in "ABCR")
        self.keys = {}
        for machine in (self.a, self.b, self.c):
            with machine:
                self.keys[machine.name] = keys.curator_key_store().public_key_hex()
        with self.a:
            monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", keys.root_key_store(Authority.VERIFIED).public_key_hex())
            monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", keys.root_key_store(Authority.COMMUNITY).public_key_hex())
        if publish_manifest:
            with self.a:
                staged = verbs.manifest_proposal(self.ctx(self.a), ProposalStore(), curator_keys=list(self.keys.values()),
                                                 curator_operators=list(self.keys), threshold=2,
                                                 promotion_author=PROMOTION_AUTHOR, root_epoch=1, version=1, legacy_uals=[])
                _, outcome = publishing.publish(self.ctx(self.a), ProposalStore(), staged.id, typed_code=None, yes=True)
                assert outcome.startswith("published"), outcome

    def ctx(self, machine, *, interest=(), sandbox=True, authority=Authority.VERIFIED):
        view = read_curator_view(machine.node, CFG, interest=interest)
        return CurateContext(cfg=CFG, client=machine.node, environment=NETWORK, view=view, sandbox=sandbox,
                             compiled=None, authority=authority)

    def two_key(self, kind, identifier, fields, *, first=None, second=None):
        """Machine *first* proposes and sends; machine *second* receives, approves and publishes."""
        first, second = first or self.a, second or self.b
        evidence = EVIDENCE if kind is Kind.CONFIRMATION else ""     # a community confirmation cites what was checked
        with first:
            proposal = verbs.propose_statement(self.ctx(first, interest=[identifier]), ProposalStore(), kind=kind,
                                               identifier=identifier, fields=fields, evidence=evidence)
            verbs.send(self.ctx(first), proposal, second.name)
        with second:
            for received in transport.receive_proposals(second.node, transport.InboxCursor()):
                ProposalStore().save(received)
            return verbs.approve(self.ctx(second, interest=[identifier]), ProposalStore(), proposal.id, evidence=evidence,
                                 typed_code=None, yes=True)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)


def _listing(reporter, **over):
    return {"listed": "yes", "class": "established", "org": "", "expires": "2026-12-31", "address": ADDRESS, **over}


# ------------------------------------------------------------------ dormant, and the flow with no access to the verified graph


@pytest.mark.parametrize("kind, identifier, fields, evidence", [
    (Kind.COUNTED_AUTHORS, "author:" + "ab" * 32, _listing(None), ""),
    (Kind.CONFIRMATION, THREAT, {}, EVIDENCE),
    (Kind.REJECTION, THREAT, {"reason": "benign"}, ""),
    (Kind.DEFERRAL, THREAT, {}, ""),
    (Kind.PAUSE, "curator", {"until": "2026-12-31"}, ""),
])
def test_while_dormant_the_tooling_signs_nothing_as_the_community_authority(tmp_path, monkeypatch, kind, identifier,
                                                                            fields, evidence):
    """No community curators for now (one graph, 2026-10-16): with a community root configured and
    curator keys on hand, no verb acts for the community authority, because no key manifest of its
    is trusted on this graph."""
    team = Curators(tmp_path, monkeypatch, publish_manifest=False)
    with team.a, pytest.raises(verbs.VerbError, match="no trusted key manifest for the community authority"):
        verbs.propose_statement(team.ctx(team.a, interest=[identifier], authority=Authority.COMMUNITY), ProposalStore(),
                                kind=kind, identifier=identifier, fields=fields, evidence=evidence)


def test_the_verified_curators_list_a_reporter_in_verified_memory_and_attest_in_shared_memory(tmp_path, monkeypatch):
    """Routed by home: the manifest and a listing (enforcement) are published to Verified Memory, an
    attestation (advisory) is shared into shared memory, and a reader sees all three."""
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    proposal, outcome = team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice))
    assert outcome.startswith(f"published to {GRAPH}") and proposal.graph == GRAPH
    _, outcome = team.two_key(Kind.ATTESTATION, THREAT, {"stage": "corroborated"})
    assert outcome.startswith(f"published to {GRAPH}")
    with team.reader:
        view = read_curator_view(team.reader.node, CFG, interest=[f"author:{alice.author}", THREAT])
    assert view.manifest.curator_keys == tuple(sorted(team.keys.values()))
    assert alice.author in view.counted and view.attestations[THREAT].field("stage") == "corroborated"
    verified = [name for (_, name) in team.net.assets[(GRAPH, VM)]]
    shared = [name for (_, name) in team.net.assets[(GRAPH, SWM)]]
    assert any(name.startswith("key-manifest-1-1") for name in verified) and any("counted-authors" in n for n in verified)
    assert [name.split("-")[1] for name in shared] == ["stage"]           # curator-stage-attestation-…


def test_one_curator_key_is_not_enough_to_list_a_reporter(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    with team.a:
        store = ProposalStore()
        proposal = verbs.propose_statement(team.ctx(team.a), store, kind=Kind.COUNTED_AUTHORS,
                                           identifier=f"author:{alice.author}", fields=_listing(alice))
        store.save(proposal.transition(ProposalState.APPROVED))        # the operator tries to skip the second key
        with pytest.raises(verbs.VerbError, match="enough curator signatures"):
            publishing.publish(team.ctx(team.a), store, proposal.id, typed_code=None, yes=True)


# ------------------------------------------------------------------ published means readable


class AcceptsAndForgets(Node):
    """A node that says the share succeeded but does not hold it (the write was lost)."""

    def share_knowledge_asset(self, cg, name, quads, **kw):
        return {"state": "succeeded"} if getattr(self, "broken", True) else super().share_knowledge_asset(cg, name, quads, **kw)


#: An advisory statement: shared into shared memory, where a write can be lost or refused.
STAGE = (Kind.ATTESTATION, THREAT, {"stage": "corroborated"})


def _approved_attestation(team):
    """A two-key attestation, approved on B but shared through a node that lost it."""
    team.b.node.__class__ = AcceptsAndForgets
    return team.two_key(*STAGE)


def test_a_write_the_node_accepted_but_that_cannot_be_read_back_is_not_published(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    proposal, outcome = _approved_attestation(team)
    assert outcome.startswith("not published") and "cannot be read back" in outcome
    with team.b:
        assert ProposalStore().get(proposal.id).state is ProposalState.APPROVED
        team.b.node.broken = False                                      # the node recovers; the operator runs publish again
        _, outcome = publishing.publish(team.ctx(team.b), ProposalStore(), proposal.id, typed_code=None, yes=True)
        assert outcome.startswith("published") and ProposalStore().get(proposal.id).state is ProposalState.PUBLISHED
    with team.reader:
        assert THREAT in read_curator_view(team.reader.node, CFG, interest=[THREAT]).attestations


def test_a_typed_consent_code_can_be_used_again_after_a_write_that_did_not_land(tmp_path, monkeypatch):
    """KI-249: outside the sandbox the operator types a code; a lost write must not strand the proposal."""
    team = Curators(tmp_path, monkeypatch)
    proposal, _ = _approved_attestation(team)
    with team.b:
        store = ProposalStore()
        envelope = store.get(proposal.id).envelope
        code = consent.confirmation_code(envelope)
        strict = team.ctx(team.b, sandbox=False)
        _, outcome = publishing.publish(strict, store, proposal.id, typed_code=code, yes=False)
        assert outcome.startswith("not published") and "read back" in outcome
        team.b.node.broken = False
        _, outcome = publishing.publish(strict, store, proposal.id, typed_code=code, yes=False)
        assert outcome.startswith("published")
        ledger = consent.ConsentLedger()
        ledger.show(envelope, "shown again after the write landed")
        assert ledger.consent(envelope, typed=code, sandbox=False, yes=False) == (False, "this code was already used (single-use)")


def test_a_refused_write_is_reported_and_can_be_retried(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    team.b.node.refuse_shares = True
    with pytest.raises(verbs.VerbError, match="the write failed, nothing was published"):
        team.two_key(*STAGE)
    with team.b:
        store = ProposalStore()
        [proposal] = store.for_identifier(THREAT)
        assert proposal.state is ProposalState.APPROVED                 # nothing was published, nothing was lost
        team.b.node.refuse_shares = False
        _, outcome = publishing.publish(team.ctx(team.b), store, proposal.id, typed_code=None, yes=True)
        assert outcome.startswith("published")


def test_another_nodes_statement_under_the_same_subject_does_not_count_as_ours(tmp_path, monkeypatch):
    """KI-250: a squatter publishes junk under the subject our statement will have; the read-back wants OUR signed text."""
    team = Curators(tmp_path, monkeypatch)
    team.b.node.__class__ = AcceptsAndForgets
    with team.a:
        from plugins.blackbox.community.statements import curator_statements as cs
        subject = cs.statement_subject(Kind.ATTESTATION, THREAT, 1)
    team.net.put(GRAPH, SWM, "squatter", "anything", [
        {"subject": subject, "predicate": "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", "object": "<http://umanitek.ai/ontology/guardian/CuratorStatement>"},
        {"subject": subject, "predicate": "http://umanitek.ai/ontology/guardian/identifier", "object": f'"{THREAT}"'},
        {"subject": subject, "predicate": "http://umanitek.ai/ontology/guardian/signedStatement", "object": '"junk"'}])
    _, outcome = team.two_key(*STAGE)
    assert outcome.startswith("not published")


def test_a_statement_the_node_already_holds_is_reported_as_already_there(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    proposal, outcome = team.two_key(*STAGE)
    assert outcome.startswith("published")
    with team.b:                                                        # the write landed but its record was lost: publish runs again
        store = ProposalStore()
        store.save(dataclasses.replace(store.get(proposal.id), state=ProposalState.APPROVED))
        _, outcome = publishing.publish(team.ctx(team.b), store, proposal.id, typed_code=None, yes=True)
    assert outcome.startswith("published") and "already held it" in outcome


# ------------------------------------------------------------------ sequence numbers


def test_a_third_machine_continues_the_numbering_whatever_kind_came_before(tmp_path, monkeypatch):
    """KI-245: C never saw A and B's proposals; it must still take number 2, not 1."""
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    identifier = f"author:{alice.author}"
    team.two_key(Kind.COUNTED_AUTHORS, identifier, _listing(alice))
    team.two_key(Kind.ATTESTATION, THREAT, {"stage": "reported"})
    with team.c:
        ctx, store = team.ctx(team.c, interest=[identifier, THREAT]), ProposalStore()
        assert publishing.next_sequence(ctx, store, identifier) == 2
        assert publishing.next_sequence(ctx, store, THREAT) == 2          # an attestation counts too, not only verdicts
        assert publishing.next_sequence(ctx, store, "ioc:ip:198.51.100.1") == 1
    _, outcome = team.two_key(Kind.COUNTED_AUTHORS, identifier, _listing(alice, listed="no"), first=team.c, second=team.a)
    assert outcome.startswith("published")
    with team.reader:
        view = read_curator_view(team.reader.node, CFG, interest=[identifier])
    assert alice.author not in view.counted and alice.author in view.delisted


# ------------------------------------------------------------------ manifests, listing defaults, acting authority


def test_a_sandbox_manifest_needs_one_operator_per_distinct_key(tmp_path, monkeypatch):
    """K2: `curate manifest` pairs --curator-key with --curator-operator by position."""
    team = Curators(tmp_path, monkeypatch, publish_manifest=False)
    keys_, operators = list(team.keys.values()), list(team.keys)
    with team.a:
        for curator_keys, curator_operators in ((keys_, operators[:2]), (keys_[:2] + keys_[:1], operators)):
            with pytest.raises(verbs.VerbError, match="exactly one operator"):
                verbs.manifest_proposal(team.ctx(team.a), ProposalStore(), curator_keys=curator_keys,
                                        curator_operators=curator_operators, threshold=2, promotion_author=PROMOTION_AUTHOR,
                                        root_epoch=1, version=1, legacy_uals=[])
        staged = verbs.manifest_proposal(team.ctx(team.a), ProposalStore(), curator_keys=keys_,
                                         curator_operators=operators, threshold=2, promotion_author=PROMOTION_AUTHOR,
                                         root_epoch=1, version=1, legacy_uals=[])
    manifest = key_manifest.parse_manifest(staged.parsed().payload)
    assert dict(zip(manifest.curator_keys, manifest.curator_operators)) == dict(zip(keys_, operators))


def test_a_listing_without_an_expiry_gets_the_authoritys_default(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    today = date(2026, 10, 3)
    with team.a:
        assert verbs.default_expiry(team.ctx(team.a), today) == "2027-10-03"                       # 365 days
        assert verbs.default_expiry(team.ctx(team.a, authority=Authority.COMMUNITY), today) == "2027-01-01"   # 90 days


def test_a_machine_acts_for_the_verified_authority_unless_told_otherwise(tmp_path, monkeypatch):
    """One graph: no community manifest is trusted, so a machine acts for the verified authority, whether
    its key is listed or only a community root is configured; an explicit choice still wins."""
    team = Curators(tmp_path, monkeypatch)
    with team.a:
        view = read_curator_view(team.a.node, CFG)
        assert view.community is None or view.community.manifest is None
        assert context.acting_authority(CFG, NETWORK, view) is Authority.VERIFIED
        assert context.acting_authority(CFG, NETWORK, view, "community") is Authority.COMMUNITY      # an explicit choice wins
    with team.reader:                                                   # a key no manifest lists, a community root configured
        assert context.acting_authority(CFG, NETWORK, read_curator_view(team.reader.node, CFG)) is Authority.VERIFIED


# ------------------------------------------------------------------ the command line


def _parse(*argv):
    import argparse

    from plugins.blackbox.curate import add_curate_parser
    parser = argparse.ArgumentParser()
    add_curate_parser(parser.add_subparsers(dest="command"))
    return parser.parse_args(["curate", *argv])


def test_the_command_line_selects_the_authority_and_needs_no_promotion_author_for_a_community_manifest():
    args = _parse("--authority", "community", "manifest", "--curator-key", "aa" * 32, "--curator-key", "bb" * 32,
                  "--curator-operator", "acme", "--curator-operator", "globex")
    assert args.authority == "community" and args.promotion_author == "" and args.issued_day == ""
    assert _parse("queue").authority is None                          # default: worked out from this machine's key


def test_each_verb_asks_for_the_statements_about_what_it_acts_on():
    from plugins.blackbox.curate import commands
    key = "CD" * 32
    assert commands._interest(_parse("propose", "--nominate", key, "--address", ADDRESS)) == [f"author:{key.lower()}"]
    assert commands._interest(_parse("propose", "--verdict", "confirmation", THREAT)) == [THREAT]
    assert commands._interest(_parse("propose", "--attest", "corroborated", THREAT)) == [THREAT]
    assert commands._interest(_parse("show", THREAT)) == [THREAT]
    assert commands._interest(_parse("queue")) == []


# ------------------------------------------------------------------ R4: the pulse withdraws revoked rules (D26)


class _TwinGraph:
    """The community graph as the pulse probes it: curator statements in shared
    memory, to which the verified authority adds a revocation's advisory twin."""

    def __init__(self):
        self.statements = []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "GROUP BY ?t" in sparql and self.statements:
            return [{"t": "http://umanitek.ai/ontology/guardian/CuratorStatement",
                     "n": str(len(self.statements)), "last": self.statements[-1]}]
        return []


def test_a_revocations_advisory_twin_makes_the_next_pulse_withdraw_the_blocked_rule(tmp_path, monkeypatch):
    """trust-and-threat-lab R4 / D26: no full refresh, and nothing raised — an identifier the view
    no longer lists stays revoked, and the kill list and manifest state are not touched."""
    from types import SimpleNamespace

    from plugins.blackbox import community, detection
    from plugins.blackbox.ruleset import community_tier, compiler, curator_tier, live, pulse_beat, refresh_cycle

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    community.PULSE.reset()
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    monkeypatch.setattr(pulse_beat.community, "ensure_community_subscription", lambda client, cfg: None)
    monkeypatch.setattr(refresh_cycle, "_retry_shares", lambda client, cfg: None)
    for full_path in ("refresh", "_refresh_unlocked", "_apply_overlays"):
        monkeypatch.setattr(refresh_cycle, full_path, lambda *a, **k: pytest.fail("the pulse ran a full refresh"))
    monkeypatch.setattr(curator_tier, "apply_curator_tier", lambda *a, **k: pytest.fail("raising overlay on the pulse"))
    monkeypatch.setattr(curator_tier, "_apply_kill_list", lambda *a, **k: pytest.fail("kill list on the pulse"))
    order = []
    monkeypatch.setattr(community_tier, "reapply_community_tier", lambda rs, client, cfg: order.append(
        ("community", frozenset(rs.curator_revoked))))
    blocked, earlier = "dep:npm:evil-pkg@1.2.3", "dep:npm:old-pkg@1.0.0"
    view = SimpleNamespace(revoked=frozenset())
    monkeypatch.setattr(curator_tier.community, "read_curator_view", lambda client, cfg, *a, **k: view)
    graph = _TwinGraph()
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: graph)

    cfg = BlackboxConfig(report=True, context_graph_id=VM_GRAPH, community_poll_interval=20)
    rule = {"identifier": blocked, "source": "public", "severity": "critical", "kind": "malware",
            "ecosystem": "npm", "packageName": "evil-pkg", "packageVersion": "1.2.3"}
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH, dependency={"npm:evil-pkg@1.2.3": rule},
                          curator_revoked=frozenset({earlier}), kill_list={"sentinel": "kept"},
                          verified_scope=live.VerifiedScope(context_graph_id=VM_GRAPH,
                                                            revoked_identifiers=frozenset({earlier})))
    rs.synced_at = time.time()
    rs.curator_manifest_state = "PENDING until 2026-10-14"
    refresh_cycle._memory.store(rs)
    install = {"command": "npm install evil-pkg@1.2.3"}
    assert [f.confirmed for f in detection.detect_dependency("bash", install, rs)] == [True]
    community.PULSE.changed(graph, cfg)                                 # baseline, as a full refresh leaves it

    graph.statements.append("urn:curator:revocation-twin")              # the advisory twin lands
    view.revoked = frozenset({blocked})                                 # ... and the revocation is readable
    pulse_beat._background_pulse(cfg)                                   # the beat, run in-line

    after = refresh_cycle.peek(cfg)
    assert detection.detect_dependency("bash", install, after) == []
    assert after.curator_revoked == {blocked, earlier}                  # the older revocation is not undone
    assert after.verified_scope.revoked_identifiers == {blocked, earlier}
    assert after.kill_list == {"sentinel": "kept"} and after.curator_manifest_state == "PENDING until 2026-10-14"
    assert order == [("community", frozenset({blocked, earlier}))]      # the full refresh's order: curator, then community
    community.PULSE.reset()
