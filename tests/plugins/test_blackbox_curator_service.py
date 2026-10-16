"""Community Curation C9 — the curator service's beat.

Three curator machines, a reader and reporters share one in-memory network
(``_machines``); reports are built by the product's own writer. Each curator
machine runs its own :class:`Beat` with its OWN advisory lookup, so a test can
make one node find an advisory and another not.

The item's done-when: a malicious dependency reported by a trusted reporter is
CONFIRMED on a reader with no human command, and every human-only action is
refused by the service.
"""

from __future__ import annotations

import dataclasses
import json
import threading
import time
from datetime import date, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from _clock import utc_today
from _community_rows import GRAPH, NETWORK, Reporter
from _machines import SWM, share_report
from test_blackbox_curate_community import CFG, EVIDENCE, Curators, _listing

from plugins.blackbox.community import CuratorView, read_curator_view, reputation
from plugins.blackbox import cli, curate
from plugins.blackbox.curate import intake, keys, queue, service, transport, verbs
from plugins.blackbox.curate.context import DISPUTE_INTAKE_STATEMENT, CurateContext
from plugins.blackbox.curate.lab import Check, NoteCode, validate_evidence
from plugins.blackbox.curate.ladder import outcomes
from plugins.blackbox.curate.proposal import Proposal, ProposalState, ProposalStore
from plugins.blackbox.curate.service import Beat, Lookup, OwnCheck, PolicyConsent, policy
from plugins.blackbox.curate.service import budget as service_budget
from plugins.blackbox.curate.service import disputes, never_promote, self_test, verdicts
from plugins.blackbox.curate.service.report import DISPUTE_ROUTE
from plugins.blackbox.curate.service.verdicts import NotProvenStep, Tier, Verdict, VerdictFacts, decide_verdict
from plugins.blackbox.curate.service.steps import ServiceSteps
from plugins.blackbox.curate.sources import (LookupBudget, LookupResult, SourceRegistry, SourceTerms, SourceVerdict,
                                             TokenBucket, WithdrawalWatcher)
from plugins.blackbox.curate.watch import SigningLog
from plugins.blackbox.detection import osv
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel.health import HealthClass
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

PKG = "dep:npm:evil-pkg@1.0.0"
IP = "ioc:ip:203.0.113.7"
TODAY = utc_today().isoformat()
FOUND = OwnCheck(Lookup.FOUND, "MAL-2026-1")
CLEAN, UNAVAILABLE = OwnCheck(Lookup.CLEAN), OwnCheck(Lookup.UNAVAILABLE)
DAY = 86_400


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(outcomes.osv, "lookup", lambda ecosystem, name, version: None)        # no network in the crediting step
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)


class Corroborated:
    """A compiled tier in which every threat it is given is CORROBORATED by counted reporters."""

    def __init__(self, *identifiers):
        self.community = {identifier: {"identifier": identifier, "stage": "corroborated", "enforcement": "flag", "counted": "8",
                                       "reporterCount": 8, "stageReason": "corroborated", "reportReason": "typosquat",
                                       "unlistedReporters": "0"} for identifier in identifiers}

    def iter_rules(self):
        return []


class NodeSource:
    """One node's stand-in for the outside sources: it answers with that node's own lookup."""

    name = "osv"
    terms = SourceTerms(citable=True, reuse_state="cleared", limit_requests=10_000, limit_seconds=1)

    def __init__(self, lookup):
        self._lookup = lookup

    def check(self, identifier):
        check = self._lookup(identifier)
        return SourceVerdict(check.status, advisory=check.advisory, source=self.name, reference_id=check.advisory)


class NeverCached:
    """A not-listed cache that remembers nothing (a test changes the answers between beats)."""

    def is_not_listed(self, source, identifier):
        return False

    def remember_not_listed(self, source, identifier):
        pass

    def forget(self, source, identifier):
        pass


def node_sources(lookup):
    return SourceRegistry([NodeSource(lookup)], cache=NeverCached())


class Service:
    """Curators A, B, C (policy accepted unless told otherwise), each with its own beat and its own lookup."""

    def __init__(self, tmp_path, monkeypatch, *, accepted="ABC"):
        self.team = Curators(tmp_path, monkeypatch)
        self.machines = {m.name: m for m in (self.team.a, self.team.b, self.team.c)}
        self.alice = Reporter("0xa")
        self.team.two_key(Kind.COUNTED_AUTHORS, f"author:{self.alice.author}", _listing(self.alice))   # a person listed alice
        self.answers = {}        # (machine name, identifier) or identifier -> OwnCheck
        self.compiled = {}       # machine name -> a compiled tier to use instead of the real one
        for name in accepted:
            self.accept(name)

    def accept(self, name):
        with self.machines[name]:
            PolicyConsent().accept(service.policy_text(), key_hex=self.team.keys[name], day=TODAY)

    def report(self, identifier, reporter=None, **kw):
        share_report(self.team.reader.node, identifier, reporter or self.alice, **kw)

    def ctx(self, machine, interest):
        ctx = self.team.ctx(machine, interest=interest)
        compiled = self.compiled.get(machine.name)
        if compiled is None:
            compiled = compiler.Ruleset()
            community_tier.apply_community_tier(compiled, machine.node, CFG, None)
        return dataclasses.replace(ctx, compiled=compiled)

    def beat(self, name, *, peers=None, clock=time.time, tester=None, **steps):
        """One beat of curator *name*: its sources answer with its own lookup; *steps* adds the other new steps."""
        machine = self.machines[name]
        others = [other for other in self.machines if other != name] if peers is None else peers

        def lookup(identifier):
            default = CLEAN if identifier.startswith("dep:") and not identifier.endswith("@*") else OwnCheck(Lookup.NOT_APPLICABLE)
            return self.answers.get((name, identifier), self.answers.get(identifier, default))

        with machine:
            return Beat(lambda interest: self.ctx(machine, interest), peers=others, lookup=lookup, clock=clock,
                        tester=tester, steps=ServiceSteps(sources=node_sources(lookup), **steps)).run()

    def view(self, *interest):
        """What a plain reader sees about *interest* (and alice)."""
        with self.team.reader:
            return read_curator_view(self.team.reader.node, CFG, interest=[*interest, f"author:{self.alice.author}"])

    def verdict(self, identifier):
        view = self.view(identifier)
        return view.verdicts.get(identifier), view

    def inbox(self, name):
        return len(self.team.net.inbox.get(name, []))

    def proposals(self, name):
        with self.machines[name]:
            return ProposalStore().all()

    def statements(self, kind):
        """The asset names of the curator statements of one kind on the shared graph."""
        return [name for (_, name) in self.team.net.assets.get((GRAPH, SWM), {}) if name.startswith(f"curator-{kind}-")]


@pytest.fixture
def svc(tmp_path, monkeypatch):
    return Service(tmp_path, monkeypatch)


# ------------------------------------------------------------------ the done-when


def test_a_malicious_dependency_is_confirmed_on_a_reader_with_no_human_command(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND                                            # every node finds the advisory ITSELF
    first = svc.beat("A")
    assert first.may_sign and first.heartbeat == "published" and len(first.proposed) == 1 and first.errors == ()
    assert svc.verdict(PKG)[0] is None                                  # one signature publishes nothing
    second = svc.beat("B")
    assert second.received == 1 and len(second.cosigned) == 1 and second.errors == ()
    record, view = svc.verdict(PKG)
    assert record.kind is Kind.CONFIRMATION and record.field("evidence") == "advisory:MAL-2026-1" and len(record.signers) == 2
    assert view.verdict(PKG) is Kind.CONFIRMATION and set(view.heartbeats) == {svc.team.keys["A"], svc.team.keys["B"]}
    again = svc.beat("A")                                               # nothing left to do, and nothing repeated
    assert again.proposed == () and again.heartbeat == "not due" and again.credited == 1
    assert len(svc.statements("confirmation")) == 1 and len(svc.statements("heartbeat")) == 2


def test_the_reader_then_flags_the_package(svc):
    svc.report(PKG, Reporter("0xnew"))                                  # only an UNLISTED reporter and alice's listing…
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.beat("A"), svc.beat("B")
    with svc.team.reader:
        tier = compiler.Ruleset()
        community_tier.apply_community_tier(tier, svc.team.reader.node, CFG, None)
    assert (tier.community[PKG]["stage"], tier.community[PKG]["enforcement"]) == ("corroborated", "flag")
    assert "confirmed by the curator" in tier.community[PKG]["stageReason"]


def test_every_statement_the_service_signs_is_recorded_as_standing_consent(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND

    def consents():
        with svc.machines["B"]:
            lines = (keys.curate_home() / "consent.jsonl").read_text(encoding="utf-8").splitlines()
        return [json.loads(line)["why"] for line in lines if json.loads(line)["event"] == "consent"]

    before = len(consents())                                             # the person's own consents during the setup
    svc.beat("A"), svc.beat("B")
    reasons = consents()[before:]
    assert any(why.startswith("standing consent: confirm: this node found MAL-2026-1") for why in reasons)
    assert any(why.startswith("standing consent: heartbeat: ") for why in reasons) and len(reasons) == 2
    assert all(why.startswith("standing consent: ") and service.policy_hash()[:8] in why for why in reasons)


# ------------------------------------------------------------------ what is NOT confirmed


@pytest.mark.parametrize("what", ["another version", "a vulnerability advisory only", "the lookup failed", "a whole package"])
def test_the_first_node_does_not_propose_without_its_own_malicious_package_advisory(svc, what):
    identifier = "dep:npm:evil-pkg@*" if what == "a whole package" else PKG
    svc.report(identifier)
    svc.answers["dep:npm:evil-pkg@1.0.1"] = FOUND                       # the advisory names ANOTHER version
    if what == "the lookup failed":
        svc.answers[PKG] = UNAVAILABLE
    report = svc.beat("A")
    assert report.proposed == () and svc.statements("confirmation") == []
    assert any(item.subject == identifier for item in report.human)


def test_a_vulnerability_advisory_is_not_evidence_of_malware():
    vulnerability = lambda eco, name, version: ("found", {"advisory_id": "GHSA-aaaa-bbbb-cccc", "severity": "high", "kind": "vulnerability"})
    malware = lambda eco, name, version: ("found", {"advisory_id": "MAL-2026-1", "severity": "critical", "kind": "malware"})
    assert service.own_check(PKG, vulnerability) == CLEAN
    assert service.own_check(PKG, malware) == FOUND and service.own_check(PKG, malware).evidence == "advisory:MAL-2026-1"
    assert service.own_check(PKG, lambda *a: ("clean", None)) == CLEAN
    assert service.own_check(PKG, lambda *a: ("unavailable", None)) == UNAVAILABLE
    for identifier in ("dep:npm:evil-pkg@*", IP, "skill:evil@1.0.0", "ioc:domain:evil.example"):
        assert service.own_check(identifier, malware).status is Lookup.NOT_APPLICABLE


def test_the_public_source_tells_nothing_found_from_could_not_ask(monkeypatch):
    answers = {"evil-pkg": {"vulns": [{"id": "GHSA-x"}, {"id": "MAL-2026-1"}]}, "clean-pkg": {}, "down": None}
    monkeypatch.setattr(osv, "_query", lambda eco, name, version: answers[name])
    assert osv.advisory_status("npm", "evil-pkg", "1.0.0") == ("found", {"advisory_id": "MAL-2026-1", "severity": "high", "kind": "malware"})
    assert osv.advisory_status("npm", "clean-pkg", "1.0.0") == ("clean", None)
    assert osv.advisory_status("npm", "down", "1.0.0") == ("unavailable", None)
    assert osv.advisory_status("npm", "evil-pkg", "") == ("unavailable", None)
    assert osv.advisory_status("no-such-ecosystem", "evil-pkg", "1.0.0") == ("unavailable", None)


@pytest.mark.parametrize("what", ["its lookup failed", "it found nothing", "it found another advisory"])
def test_a_proposal_the_second_node_cannot_reproduce_is_not_co_signed_and_waits_for_a_person(svc, what):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.answers[("B", PKG)] = {"its lookup failed": UNAVAILABLE, "it found nothing": CLEAN,
                               "it found another advisory": OwnCheck(Lookup.FOUND, "MAL-2026-9")}[what]
    proposed = svc.beat("A").proposed
    report = svc.beat("B")
    assert report.cosigned == () and svc.statements("confirmation") == [] and svc.verdict(PKG)[0] is None
    assert [item.subject for item in report.human if item.subject == proposed[0]] == [proposed[0]]
    assert [p.state for p in svc.proposals("B") if p.id == proposed[0]] == [ProposalState.PROPOSED]      # left for a person
    assert [len(p.parsed().signatures) for p in svc.proposals("B") if p.id == proposed[0]] == [1]        # and not co-signed


# ------------------------------------------------------------------ standing consent


def test_without_the_accepted_policy_the_service_signs_nothing(tmp_path, monkeypatch):
    svc = Service(tmp_path, monkeypatch, accepted="")
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    def state():
        signed = [(p.id, len(p.parsed().signatures)) for p in svc.proposals("A")]            # every signature this machine holds
        return dict(svc.team.net.assets[(GRAPH, SWM)]), signed, svc.inbox("B")

    before = state()
    report = svc.beat("A")
    assert not report.may_sign and "not accepted" in report.why_not and report.heartbeat == "not signed"
    assert report.proposed == () and report.published == ()
    assert state() == before                                             # nothing signed, nothing written, nothing sent
    assert any("the policy allows the service to do this" in item.why for item in report.human)   # a person can still do it
    svc.accept("A")
    assert len(svc.beat("A").proposed) == 1


def test_a_changed_policy_text_stops_the_service_until_it_is_accepted_again(svc, monkeypatch):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    monkeypatch.setattr(policy, "SERVICE_LISTINGS_PER_DAY", 7)           # the policy text changes
    report = svc.beat("A")
    assert not report.may_sign and report.proposed == () and svc.statements("heartbeat") == []
    svc.accept("A")
    assert len(svc.beat("A").proposed) == 1


def test_a_machine_whose_key_is_not_a_curator_key_signs_nothing(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    reader = svc.team.reader
    with reader:
        PolicyConsent().accept(service.policy_text(), key_hex=keys.curator_key_store().public_key_hex(), day=TODAY)
        report = Beat(lambda interest: svc.ctx(reader, interest), peers=["A"], lookup=lambda identifier: FOUND).run()
    assert not report.may_sign and "not a curator key" in report.why_not and report.proposed == ()


# ------------------------------------------------------------------ what only a person may do


def _human_proposal(svc, kind, identifier, fields, evidence=""):
    """A PERSON on machine A proposes and sends it to B."""
    with svc.team.a:
        proposal = verbs.propose_statement(svc.team.ctx(svc.team.a, interest=[identifier]), ProposalStore(), kind=kind,
                                           identifier=identifier, fields=fields, evidence=evidence)
        verbs.send(svc.team.ctx(svc.team.a), proposal, "B")
    return proposal


@pytest.mark.parametrize("what", ["a rejection", "a partner grant", "a collapse", "a pause", "a confirmation of an indicator",
                                  "a confirmation citing a reproduction", "a listing its ledger does not call for"])
def test_the_service_never_co_signs_what_only_a_person_may_decide(svc, what):
    bob = Reporter("0xb")
    svc.report(PKG), svc.report(IP)
    svc.answers[PKG] = FOUND
    kind, identifier, fields, evidence = {
        "a rejection": (Kind.REJECTION, PKG, {"reason": "benign"}, ""),
        "a partner grant": (Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob, **{"class": "partner", "org": "acme"}), ""),
        "a collapse": (Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob, org="one-operator"), ""),
        "a pause": (Kind.PAUSE, "curator", {"until": (utc_today() + timedelta(days=3)).isoformat()}, ""),
        "a confirmation of an indicator": (Kind.CONFIRMATION, IP, {}, EVIDENCE),
        "a confirmation citing a reproduction": (Kind.CONFIRMATION, PKG, {}, "reproduced:" + "ab" * 32),
        "a listing its ledger does not call for": (Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob), ""),
    }[what]
    proposal = _human_proposal(svc, kind, identifier, fields, evidence)
    before = set(svc.team.net.assets[(GRAPH, SWM)])
    report = svc.beat("B", peers=[])
    assert proposal.id not in report.cosigned and proposal.id in [item.subject for item in report.human]
    written = {name for (_, name) in set(svc.team.net.assets[(GRAPH, SWM)]) - before}
    assert all(name.startswith(("curator-heartbeat-", "curator-in-review-")) for name in written), written
    assert [p.state for p in svc.proposals("B") if p.id == proposal.id] == [ProposalState.PROPOSED]


def test_a_person_can_still_approve_what_the_service_left(svc):
    svc.report(IP)
    proposal = _human_proposal(svc, Kind.CONFIRMATION, IP, {}, EVIDENCE)
    svc.beat("B", peers=[])
    with svc.team.b:
        _, outcome = verbs.approve(svc.team.ctx(svc.team.b, interest=[IP]), ProposalStore(), proposal.id, evidence=EVIDENCE,
                                   typed_code=None, yes=True)
    assert outcome.startswith("published") and svc.verdict(IP)[0].kind is Kind.CONFIRMATION


def test_messages_that_are_not_a_curators_proposal_are_dropped(svc):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    svc.report(PKG)
    genuine = _human_proposal(svc, Kind.REJECTION, PKG, {"reason": "benign"})
    outsider = Ed25519PrivateKey.generate()                              # gitleaks:allow — a throwaway test key
    with svc.team.a:
        manifest = svc.team.ctx(svc.team.a).manifest
    forged = signing.sign(outsider, statement_type=Kind.REJECTION.value, environment=manifest.environment, graph=GRAPH,
                          payload={"identifier": PKG, "day": TODAY, "reason": "benign"}, chain=manifest.chain,
                          root_epoch=manifest.root_epoch, sequence=9)
    wrong_id = dataclasses.replace(genuine, id="0" * 16)
    outsiders = Proposal.new(Kind.REJECTION.value, PKG, forged, GRAPH, checks={}).transition(ProposalState.PROPOSED)   # consistent, unsigned by a curator
    node = svc.team.reader.node
    for text in (transport.PROPOSAL_PREFIX + outsiders.to_json(),
                 transport.PROPOSAL_PREFIX + wrong_id.to_json(), transport.PROPOSAL_PREFIX + "{not json", "hello"):
        node.request("POST", "/api/chat", {"to": "B", "text": text})
    report = svc.beat("B", peers=[])
    assert (report.received, report.dropped) == (1, 2)                   # the two non-proposals are not even counted
    assert [p.id for p in svc.proposals("B") if p.kind == Kind.REJECTION.value] == [genuine.id]


# ------------------------------------------------------------------ nothing is left half-done


def test_a_beat_that_fails_halfway_leaves_nothing_half_published_and_the_next_beat_completes_it(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    proposed = svc.beat("A").proposed
    svc.team.b.node.refuse_shares = True                                 # B's node refuses every write
    broken = svc.beat("B")
    assert broken.cosigned == () and broken.errors and svc.statements("confirmation") == [] and svc.verdict(PKG)[0] is None
    assert [p.state for p in svc.proposals("B") if p.id == proposed[0]] == [ProposalState.APPROVED]     # signed, not published
    svc.team.b.node.refuse_shares = False
    mended = svc.beat("B")
    assert mended.cosigned == (proposed[0],) and mended.heartbeat == "published" and mended.errors == ()
    assert len(svc.statements("confirmation")) == 1 and svc.verdict(PKG)[0].kind is Kind.CONFIRMATION
    assert svc.beat("B").cosigned == ()                                  # and it is not published twice
    assert len(svc.statements("heartbeat")) == 2                         # A's and B's: B finished the one it had signed


def test_one_item_failing_never_stops_the_step_reaching_the_others(svc):
    """With the node refusing writes, EVERY proposal is co-signed and waits to be published — which
    ones a beat reaches must not depend on the order they are read in."""
    packages = [f"dep:npm:evil-{n}@1.0.0" for n in range(4)]
    for package in packages:
        svc.report(package)
        svc.answers[package] = FOUND
    proposed = set(svc.beat("A").proposed)
    svc.team.b.node.refuse_shares = True
    broken = svc.beat("B")
    assert len(proposed) == 4 and len(broken.errors) >= 4
    assert {p.id for p in svc.proposals("B") if p.state is ProposalState.APPROVED and p.id in proposed} == proposed
    svc.team.b.node.refuse_shares = False
    assert set(svc.beat("B").cosigned) == proposed and len(svc.statements("confirmation")) == 4


def test_the_beat_keeps_this_nodes_statements_alive_and_only_with_consent(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.beat("A"), svc.beat("B")                                         # B published the confirmation
    assert svc.beat("B").kept_alive == 0                                 # the same keep-alive epoch: nothing due
    later = lambda: time.time() + 11 * DAY
    with svc.machines["B"]:
        PolicyConsent().withdraw()
    assert svc.beat("B", clock=later).kept_alive == 0                    # no standing consent: nothing is re-published
    svc.accept("B")
    assert svc.beat("B", clock=later).kept_alive >= 1


def test_a_proposal_that_reached_nobody_is_sent_again(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    start = svc.inbox("B")
    alone = svc.beat("A", peers=[])
    assert len(alone.proposed) == 1 and any("reached no other curator" in error for error in alone.errors)
    assert svc.inbox("B") == start
    again = svc.beat("A")
    assert again.proposed == () and svc.inbox("B") == start + 1          # the SAME proposal, now delivered
    assert svc.beat("A").errors == () and svc.inbox("B") == start + 1    # and not sent a third time
    assert len(svc.beat("B").cosigned) == 1


def test_a_half_signed_copy_on_the_graph_does_not_finish_this_nodes_proposal(svc):
    """Anyone can publish the first curator's single signature; the proposal is finished only when the statement has its quorum."""
    from plugins.blackbox.community.statements import curator_statements as cs
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    proposed = svc.beat("A").proposed
    with svc.machines["A"]:
        envelope = ProposalStore().get(proposed[0]).parsed()
    svc.team.reader.node.share_knowledge_asset(GRAPH, "half-signed", cs.statement_quads(envelope))
    svc.beat("A")
    assert [p.state for p in svc.proposals("A") if p.id == proposed[0]] == [ProposalState.PROPOSED]
    svc.beat("B"), svc.beat("A")                                         # B co-signs and publishes: now it is finished
    assert [p.state for p in svc.proposals("A") if p.id == proposed[0]] == [ProposalState.PUBLISHED]


def test_a_proposal_this_node_already_acted_on_is_not_reset_by_receiving_it_again(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    proposed = svc.beat("A").proposed
    svc.beat("B")
    with svc.team.a:
        verbs.send(svc.team.ctx(svc.team.a), ProposalStore().get(proposed[0]), "B")       # the same proposal arrives again
    report = svc.beat("B")
    assert report.received == 0 and report.cosigned == ()
    assert [p.state for p in svc.proposals("B") if p.id == proposed[0]] == [ProposalState.PUBLISHED]


# ------------------------------------------------------------------ the service's own daily limit


def test_the_service_signs_at_most_its_daily_limit_and_goes_on_the_next_day(svc, monkeypatch):
    monkeypatch.setattr(policy, "SERVICE_CONFIRMATIONS_PER_DAY", 2)
    svc.accept("A")                                                      # the limit is part of the policy text
    packages = [f"dep:npm:evil-{n}@1.0.0" for n in range(3)]
    for package in packages:
        svc.report(package)
        svc.answers[package] = FOUND
    today = svc.beat("A")
    assert len(today.proposed) == 2 and today.limited == 1
    assert svc.beat("A").proposed == ()
    tomorrow = svc.beat("A", clock=lambda: time.time() + DAY)
    assert len(tomorrow.proposed) == 1 and tomorrow.limited == 0


def test_a_co_signature_counts_against_the_daily_limit_too(svc, monkeypatch):
    monkeypatch.setattr(policy, "SERVICE_CONFIRMATIONS_PER_DAY", 2)
    svc.accept("A"), svc.accept("C")
    for n in range(3):
        svc.report(f"dep:npm:evil-{n}@1.0.0")
        svc.answers[f"dep:npm:evil-{n}@1.0.0"] = FOUND
    assert len(svc.beat("A", peers=["C"]).proposed) == 2
    report = svc.beat("C", peers=[])
    assert len(report.cosigned) == 2 and report.proposed == () and report.limited == 1     # the third waits for tomorrow


def test_the_budget_counts_per_day_and_per_kind(tmp_path):
    book = service_budget.ServiceBudget(tmp_path / "budget.json")
    assert book.left("confirm", TODAY) == policy.SERVICE_CONFIRMATIONS_PER_DAY and book.left("list", TODAY) == policy.SERVICE_LISTINGS_PER_DAY
    for _ in range(3):
        book.spend("confirm", TODAY)
    book.spend("list", TODAY)
    assert book.left("confirm", TODAY) == policy.SERVICE_CONFIRMATIONS_PER_DAY - 3
    assert book.left("list", TODAY) == policy.SERVICE_LISTINGS_PER_DAY - 1
    assert book.left("confirm", "2099-01-01") == policy.SERVICE_CONFIRMATIONS_PER_DAY      # another day starts from zero
    (tmp_path / "budget.json").write_text("not json", encoding="utf-8")
    assert book.left("confirm", TODAY) == policy.SERVICE_CONFIRMATIONS_PER_DAY


# ------------------------------------------------------------------ the clock: acknowledge, defer, lapse


def test_a_threat_only_a_person_can_decide_is_acknowledged_once(svc):
    svc.report(IP)
    first = svc.beat("A")
    assert first.published == (f"in-review {IP}",) and [item.subject for item in first.human] == [IP]
    assert svc.verdict(IP)[0].kind is Kind.IN_REVIEW
    second = svc.beat("A")
    assert second.published == () and [item.subject for item in second.human] == [IP] and len(svc.statements("in-review")) == 1


def test_a_corroborated_dependency_with_no_evidence_is_deferred_by_one_key_and_lapses_after_thirty_days(svc):
    svc.compiled["A"] = Corroborated(PKG)
    assert svc.beat("A").published == (f"deferral {PKG}",)               # one key is enough: it never raises enforcement
    assert svc.verdict(PKG)[0].kind is Kind.DEFERRAL
    assert svc.beat("A").published == ()                                 # deferred once
    assert svc.beat("A", clock=lambda: time.time() + 30 * DAY).published == ()
    lapsed = svc.beat("A", clock=lambda: time.time() + 31 * DAY)
    assert f"deferral-lapsed {PKG}" in lapsed.published and svc.verdict(PKG)[0].kind is Kind.DEFERRAL_LAPSED
    after = svc.beat("A", clock=lambda: time.time() + 32 * DAY)
    assert not any(done.startswith("deferral") for done in after.published)          # a lapsed deferral is not deferred again


def test_a_failed_lookup_defers_nothing_and_an_indicator_is_never_deferred(svc):
    svc.compiled["A"] = Corroborated(PKG, IP)
    svc.answers[PKG] = UNAVAILABLE
    report = svc.beat("A")
    assert not any(done.startswith("deferral") for done in report.published) and svc.statements("deferral") == []
    assert {item.subject for item in report.human} == {PKG, IP}


def test_evidence_arriving_during_a_deferral_confirms_the_threat(svc):
    svc.compiled["A"] = svc.compiled["B"] = Corroborated(PKG)
    svc.beat("A")
    assert svc.verdict(PKG)[0].kind is Kind.DEFERRAL
    svc.answers[PKG] = FOUND                                             # the advisory is published later
    assert len(svc.beat("A").proposed) == 1 and len(svc.beat("B").cosigned) == 1
    assert svc.verdict(PKG)[0].kind is Kind.CONFIRMATION


# ------------------------------------------------------------------ the ladder


def _graduating(svc, names, reporter, *, days_ago=30):
    """On each named curator machine, *reporter* has five novel confirmed reports and a first report *days_ago* back."""
    first = (utc_today() - timedelta(days=days_ago)).isoformat()
    for name in names:
        with svc.machines[name]:
            book = reputation.ReputationLedger()
            for _ in range(reputation.GRADUATION_MIN_NOVEL):
                book.record(reporter.author, reputation.Outcome(TODAY, True), novel=True, first_seen_day=first)


def test_a_graduation_both_ledgers_call_for_is_listed_with_no_human_command(svc):
    bob = Reporter("0xb")
    svc.report(IP, bob)
    _graduating(svc, "AB", bob)
    first = svc.beat("A")
    assert len(first.proposed) == 1 and svc.beat("A").proposed == ()     # one proposal in flight is enough
    assert len(svc.beat("B").cosigned) == 1
    view = svc.view(f"author:{bob.author}")
    assert bob.author in view.counted and view.counted[bob.author].author_class == "established"
    assert view.counted[bob.author].expires == (utc_today() + timedelta(days=reputation.LISTING_DAYS)).isoformat()
    assert svc.beat("A").proposed == () and svc.beat("B").proposed == ()                # listed: nothing more to propose


def test_a_graduation_the_second_ledger_does_not_call_for_waits_for_a_person(svc):
    bob = Reporter("0xb")
    svc.report(IP, bob)
    _graduating(svc, "A", bob)                                           # only A's ledger says so
    proposed = svc.beat("A").proposed
    report = svc.beat("B")
    assert report.cosigned == () and proposed[0] in [item.subject for item in report.human]
    assert bob.author not in svc.view(f"author:{bob.author}").counted


def test_a_reporter_too_new_or_one_credit_short_is_not_proposed(svc):
    young, short = Reporter("0xyoung"), Reporter("0xshort")
    svc.report(IP, young), svc.report(IP, short)
    _graduating(svc, "A", young, days_ago=13)
    with svc.machines["A"]:
        for _ in range(reputation.GRADUATION_MIN_NOVEL - 1):
            reputation.ReputationLedger().record(short.author, reputation.Outcome(TODAY, True), novel=True,
                                                 first_seen_day=(utc_today() - timedelta(days=30)).isoformat())
    assert svc.beat("A").proposed == ()


def test_a_listing_about_to_expire_is_renewed_and_one_far_from_expiry_is_not(tmp_path, monkeypatch):
    svc = Service(tmp_path, monkeypatch)                                 # alice's listing runs to 2026-12-31: not due
    assert svc.beat("A").proposed == ()
    carol = Reporter("0xc")
    soon = (utc_today() + timedelta(days=10)).isoformat()
    svc.team.two_key(Kind.COUNTED_AUTHORS, f"author:{carol.author}", _listing(carol, expires=soon))
    assert len(svc.beat("A").proposed) == 1 and len(svc.beat("B").cosigned) == 1
    assert svc.view(f"author:{carol.author}").counted[carol.author].expires == (
        utc_today() + timedelta(days=reputation.LISTING_DAYS)).isoformat()
    assert svc.beat("A").proposed == () and svc.beat("B").proposed == ()                # renewed: nothing more to propose


def test_a_reporter_under_the_reputation_floor_is_delisted_by_both_ledgers(svc):
    for name in "AB":
        with svc.machines[name]:
            book = reputation.ReputationLedger()
            outcomes.sync_bands(svc.team.ctx(svc.machines[name], interest=[f"author:{svc.alice.author}"]).own_view, book, TODAY)
            for _ in range(4):
                book.record(svc.alice.author, reputation.Outcome(TODAY, False))
    assert len(svc.beat("A").proposed) == 1 and len(svc.beat("B").cosigned) == 1
    view = svc.view()
    assert svc.alice.author not in view.counted and svc.alice.author in view.delisted


# ------------------------------------------------------------------ the command


def test_the_run_command_does_one_beat_and_says_what_happened(svc, capsys):
    svc.report(IP)
    machine = svc.machines["A"]
    with machine:
        code = service.run_command(lambda interest: svc.ctx(machine, interest), peers=["B", "C"], interval=300, once=True,
                                   steps=ServiceSteps(sources=node_sources(lambda identifier: CLEAN)))
    printed = capsys.readouterr().out
    assert code == 0 and "beat: signing · heartbeat published" in printed and "1 for a person" in printed
    assert f"for a person: {IP}" in printed and "looked up 1" in printed and "batch" not in printed


# ------------------------------------------------------------------ SVC1: the root row, and re-acceptance

#: The policy hash every curator accepted before SVC1 (root row "A PERSON, offline").
OLD_POLICY_HASH = "2e74cdf4421ccd2c21851c4b48748352a42f64b566c569397dbddff840299a2f"
OLD_ROOT_ROW = ("Anything involving the root key", "A PERSON, offline", "it is the root")


def _old_policy_text(monkeypatch):
    rows = tuple(OLD_ROOT_ROW if what == OLD_ROOT_ROW[0] else (what, who, why) for what, who, why in policy.POLICY_ROWS)
    with monkeypatch.context() as patched:
        patched.setattr(policy, "POLICY_ROWS", rows)
        return service.policy_text()


def test_the_root_row_names_the_key_console_so_the_policy_hash_moves(monkeypatch):
    root = dict((what, who) for what, who, _ in policy.POLICY_ROWS)["Anything involving the root key"]
    assert root == "A PERSON, in the key console with the passphrase and second factor"
    old_text = _old_policy_text(monkeypatch)
    assert policy.hashlib.sha256(old_text.encode("utf-8")).hexdigest() == OLD_POLICY_HASH   # the old text, rebuilt exactly
    assert service.policy_hash() != OLD_POLICY_HASH


def test_a_curator_who_accepted_the_old_policy_must_accept_again(tmp_path, monkeypatch):
    consent = PolicyConsent(tmp_path / "policy_consent.json")
    consent.accept(_old_policy_text(monkeypatch), key_hex="a" * 64, day=TODAY)
    assert not consent.accepted(service.policy_text(), "a" * 64)                  # the service stops signing
    consent.accept(service.policy_text(), key_hex="a" * 64, day=TODAY)
    assert consent.accepted(service.policy_text(), "a" * 64)


# ------------------------------------------------------------------ SVC1: the verdict rules per type

DOMAIN = "ioc:domain:login-paypa1.example"


def _run(seen=(), unseen=(), notes=()):
    """One lab run's validated Evidence: *seen* checks happened, *unseen* were answered no."""
    image = "b" * 64
    return validate_evidence({
        "job_key": f"{'a' * 64}:2:{image}", "image_sha256": image, "level": 2, "started_at": 1, "finished_at": 2,
        "contacted_hosts": [], "file_fingerprints": [],
        "observations": [{"check": c.value, "seen": True} for c in seen] + [{"check": c.value, "seen": False} for c in unseen],
        "notes": [n.value for n in notes],
    })


ALL_CHECKS = tuple(Check)
CLEAN_RUN = _run(unseen=ALL_CHECKS)


def test_a_package_a_malicious_package_advisory_lists_is_confirmed_and_may_block():
    decision = decide_verdict(PKG, VerdictFacts(citable_listing="MAL-2026-1"))
    assert decision.verdict is Verdict.CONFIRMED and decision.promotable and decision.tier is Tier.BLOCK
    assert decision.citation == "MAL-2026-1" and "MAL-2026-1" in decision.reason


@pytest.mark.parametrize("identifier", [DOMAIN, "ioc:url:https://login-paypa1.example/x", IP])
def test_an_address_the_lab_ran_clean_and_no_source_lists_is_rejected(identifier):
    decision = decide_verdict(identifier, VerdictFacts(sources_clean=True, lab=(CLEAN_RUN,)))
    assert decision.verdict is Verdict.REJECTED and not decision.promotable and decision.tier is None


@pytest.mark.parametrize("facts", [
    VerdictFacts(sources_clean=False, lab=(CLEAN_RUN,)),                                   # a source could not be asked
    VerdictFacts(sources_clean=True, lab=()),                                              # the lab never ran
    VerdictFacts(sources_clean=True, lab=(_run(unseen=ALL_CHECKS, notes=(NoteCode.DEADLINE_REACHED,)),)),  # it ran out of time
    VerdictFacts(sources_clean=True, lab=(_run(unseen=(Check.CREDENTIAL_FORM,)),)),        # it never answered the bait check
    VerdictFacts(sources_clean=True, lab=(CLEAN_RUN, _run(unseen=ALL_CHECKS, notes=(NoteCode.CLOAKING_SUSPECTED,)))),
])
def test_could_not_tell_is_never_clean_so_nothing_is_rejected(facts):
    assert decide_verdict(DOMAIN, facts).verdict is Verdict.NOT_PROVEN


def test_with_no_evidence_a_threat_is_not_proven_and_not_promoted():
    decision = decide_verdict(PKG, VerdictFacts())
    assert decision.verdict is Verdict.NOT_PROVEN and not decision.promotable and decision.tier is None


@pytest.mark.parametrize("age, retests_done, step", [
    (0, 0, NotProvenStep.KEEP_FLAGGING), (6, 0, NotProvenStep.KEEP_FLAGGING),
    (7, 0, NotProvenStep.RETEST), (10, 0, NotProvenStep.RETEST),            # a missed day 7 is caught up
    (8, 1, NotProvenStep.KEEP_FLAGGING), (20, 1, NotProvenStep.KEEP_FLAGGING),
    (21, 1, NotProvenStep.RETEST), (25, 2, NotProvenStep.KEEP_FLAGGING), (29, 2, NotProvenStep.KEEP_FLAGGING),
    (30, 2, NotProvenStep.CLOSE_UNPROVEN), (30, 0, NotProvenStep.CLOSE_UNPROVEN), (45, 2, NotProvenStep.CLOSE_UNPROVEN),
])
def test_a_not_proven_threat_is_re_tested_on_days_7_and_21_and_closes_unproven_at_30(age, retests_done, step):
    opened = date(2026, 10, 1)
    assert verdicts.RETEST_DAYS == (7, 21) and verdicts.NOT_PROVEN_FLAG_DAYS == 30
    assert verdicts.not_proven_step(opened.isoformat(), (opened + timedelta(days=age)).isoformat(), retests_done) is step


@pytest.mark.parametrize("address, provider", [
    ("104.16.1.1", "Cloudflare"), ("2606:4700::1", "Cloudflare"), ("151.101.1.1", "Fastly"), ("23.0.0.1", "Akamai"),
    ("52.95.110.1", "AWS"), ("2600:1f18::1", "AWS"), ("4.144.0.1", "Azure"), ("8.34.208.1", "GCP"),
])
def test_a_bare_ip_inside_a_cdn_or_cloud_range_is_not_proven_and_never_promoted(address, provider):
    decision = decide_verdict(f"ioc:ip:{address}", VerdictFacts(citable_listing="urlhaus:123", lab=(_run(seen=ALL_CHECKS),)))
    assert decision.verdict is Verdict.NOT_PROVEN and not decision.promotable and provider in decision.reason


def test_a_bare_ip_outside_every_range_is_still_promotable():
    assert never_promote.provider_for_ip("203.0.113.7") is None
    assert decide_verdict(IP, VerdictFacts(citable_listing="urlhaus:123")).promotable


@pytest.mark.parametrize("identifier", ["ioc:url:https://104.16.1.1/login", "ioc:url:https://evil.pages.example/x"])
def test_a_url_on_a_cdn_is_still_promotable(identifier):
    assert never_promote.never_promoted(identifier) is None
    decision = decide_verdict(identifier, VerdictFacts(citable_listing="urlhaus:123"))
    assert decision.verdict is Verdict.CONFIRMED and decision.promotable


def test_unreadable_ranges_promote_no_bare_ip(tmp_path, monkeypatch):
    (tmp_path / "ranges.json").write_text("not json", encoding="utf-8")
    monkeypatch.setattr(never_promote, "_RANGES_FILE", tmp_path / "ranges.json")
    never_promote.providers.cache_clear()
    try:
        decision = decide_verdict(IP, VerdictFacts(citable_listing="urlhaus:123"))
        assert decision.verdict is Verdict.NOT_PROVEN and not decision.promotable
        assert decide_verdict(PKG, VerdictFacts(citable_listing="MAL-2026-1")).promotable   # only bare IPs wait on the ranges
    finally:
        never_promote.providers.cache_clear()


def test_the_ranges_are_held_with_their_source_and_date():
    held = {ranges.provider: ranges for ranges in never_promote.providers()}
    assert set(held) == {"Cloudflare", "Akamai", "Fastly", "AWS", "Azure", "GCP"}
    for ranges in held.values():
        assert ranges.source.startswith("https://") and ranges.list_version and date.fromisoformat(ranges.fetched)
        assert ranges.intervals[4]


NEVER_FLAG = frozenset({"ioc:ip:8.8.8.8", "ioc:domain:dns.google", PKG})


@pytest.mark.parametrize("identifier", ["ioc:ip:8.8.8.8", "ioc:domain:dns.google"])
def test_an_exact_never_flag_entry_is_rejected_even_when_listed(identifier):
    decision = decide_verdict(identifier, VerdictFacts(citable_listing="urlhaus:123"), NEVER_FLAG)
    assert decision.verdict is Verdict.REJECTED and not decision.promotable


@pytest.mark.parametrize("identifier", ["ioc:ip:8.8.8.9", "ioc:domain:dns.google.evil.example", "ioc:domain:xdns.google",
                                        "ioc:url:https://dns.google/x"])
def test_a_near_match_of_a_never_flag_entry_is_not_rejected(identifier):
    assert decide_verdict(identifier, VerdictFacts(), NEVER_FLAG).verdict is Verdict.NOT_PROVEN
    assert decide_verdict(identifier, VerdictFacts(citable_listing="urlhaus:123"), NEVER_FLAG).verdict is Verdict.CONFIRMED


def test_never_flag_never_applies_to_a_package():
    assert decide_verdict(PKG, VerdictFacts(citable_listing="MAL-2026-1"), NEVER_FLAG).verdict is Verdict.CONFIRMED


@pytest.mark.parametrize("identifier, proof", [
    (PKG, (Check.INSTALL_SCRIPT_RAN, Check.FILE_WRITTEN_OUTSIDE_PACKAGE)),
    ("skill:evil-skill@1.0.0", (Check.BAIT_CREDENTIAL_SENT,)),
    (DOMAIN, (Check.BAIT_CREDENTIAL_SENT,)),
])
def test_a_lab_only_confirmation_is_flag_tier_for_every_type(identifier, proof):
    decision = decide_verdict(identifier, VerdictFacts(lab=(_run(seen=proof),)))
    assert decision.verdict is Verdict.CONFIRMED and decision.promotable and decision.tier is Tier.FLAG


@pytest.mark.parametrize("identifier, seen", [
    (PKG, (Check.INSTALL_SCRIPT_RAN, Check.PROCESS_SPAWNED, Check.NETWORK_CONTACTED)),   # a prebuilt-binary download
    (DOMAIN, (Check.CREDENTIAL_FORM, Check.REDIRECTED_OFF_DOMAIN)),                     # a single-sign-on login page
    ("injection:ignore-previous", ALL_CHECKS),                                          # no lab proof rule for the type
])
def test_signs_an_honest_target_also_shows_prove_nothing(identifier, seen):
    assert decide_verdict(identifier, VerdictFacts(lab=(_run(seen=seen),))).verdict is Verdict.NOT_PROVEN


# ------------------------------------------------------------------ SVC2: self-test with auto-suspend; delivery alarm


def _one_wrong(identifier="dep:npm:self-test-evil@1.0.0"):
    """The real verdict rules, except one fixture gets the wrong verdict."""
    def decide(candidate, facts, never_flag):
        right = decide_verdict(candidate, facts, never_flag)
        if candidate != identifier:
            return right
        wrong = Verdict.CONFIRMED if right.verdict is Verdict.REJECTED else Verdict.REJECTED
        return verdicts.VerdictDecision(wrong, "wrong on purpose")
    return decide


def _signed_by(svc, name):
    """Everything machine *name* has signed: its proposals' signatures and its signing log."""
    with svc.machines[name]:
        return [(p.id, len(p.parsed().signatures)) for p in ProposalStore().all()], len(SigningLog().rows())


def test_the_fixture_set_is_10_threats_10_clean_and_2_could_not_tell():
    expected = [case.expected for case in self_test.fixtures()]
    assert (expected.count(Verdict.CONFIRMED), expected.count(Verdict.REJECTED), expected.count(Verdict.NOT_PROVEN)) == (10, 10, 2)
    assert len({case.identifier for case in self_test.fixtures()}) == 22


def test_this_nodes_verdict_rules_pass_22_of_22_and_the_curator_is_not_suspended(svc):
    result = self_test.run_self_test(TODAY)
    assert (result.matched, result.total, result.passed, result.failures) == (22, 22, True, ())
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    report = svc.beat("A")
    assert report.may_sign and len(report.proposed) == 1
    with svc.machines["A"]:
        assert self_test.SelfTestStore().read().passed and curate.status_health_items(time.time()) == []


@pytest.mark.parametrize("identifier", ["dep:npm:self-test-evil@1.0.0", "ioc:domain:never-flag.self-test.invalid",
                                        "dep:npm:self-test-timeout@1.0.0"])
def test_one_wrong_verdict_fails_the_self_test(identifier):
    result = self_test.run_self_test(TODAY, _one_wrong(identifier))
    assert not result.passed and result.matched == 21 and identifier in result.failures[0]


def test_a_lab_only_confirmation_at_block_tier_fails_the_self_test():
    def blocks_on_lab(candidate, facts, never_flag):
        decision = decide_verdict(candidate, facts, never_flag)
        return dataclasses.replace(decision, tier=Tier.BLOCK) if decision.tier is Tier.FLAG else decision
    assert self_test.run_self_test(TODAY, blocks_on_lab).matched == 16


def test_a_verdict_rule_that_raises_fails_every_case_it_raised_on():
    def broken(candidate, facts, never_flag):
        raise RuntimeError("boom")
    result = self_test.run_self_test(TODAY, broken)
    assert not result.passed and result.matched == 0 and "RuntimeError" in result.failures[0]


def test_a_suspended_curator_makes_no_first_signature_and_a_passing_rerun_lifts_it(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    before, inbox = _signed_by(svc, "A"), svc.inbox("B")
    report = svc.beat("A", tester=self_test.SelfTest(decide=_one_wrong()))
    assert not report.may_sign and "suspended" in report.why_not and report.heartbeat == "not signed"
    assert report.proposed == () and report.published == ()
    assert _signed_by(svc, "A") == before and svc.inbox("B") == inbox     # nothing signed, nothing sent
    assert svc.beat("A", tester=self_test.SelfTest(decide=_one_wrong())).proposed == ()   # still suspended next beat
    lifted = svc.beat("A")                                                # a passing run (the real rules)
    assert lifted.may_sign and len(lifted.proposed) == 1


def test_a_suspended_curator_does_not_co_sign_and_a_passing_rerun_lifts_it(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    assert len(svc.beat("A").proposed) == 1
    before = _signed_by(svc, "B")
    report = svc.beat("B", tester=self_test.SelfTest(decide=_one_wrong()))
    assert report.cosigned == () and report.published == () and "suspended" in report.why_not
    assert _signed_by(svc, "B")[1] == before[1]                           # the signing log holds no new row
    assert len(svc.beat("B").cosigned) == 1


def test_a_passing_run_is_not_repeated_the_same_day_but_is_the_next_and_a_failing_one_every_beat(tmp_path):
    calls = []
    def counting(candidate, facts, never_flag):
        calls.append(candidate)
        return decide_verdict(candidate, facts, never_flag)
    tester = self_test.SelfTest(self_test.SelfTestStore(tmp_path / "self_test.json"), decide=counting)
    tester.check("2026-10-11")
    tester.check("2026-10-11")
    assert len(calls) == 22                                               # run once at start, not again today
    tester.check("2026-10-12")
    assert len(calls) == 44                                               # daily
    wrong, failing_calls = _one_wrong(), []
    def failing_rule(candidate, facts, never_flag):
        failing_calls.append(candidate)
        return wrong(candidate, facts, never_flag)
    failing = self_test.SelfTest(self_test.SelfTestStore(tmp_path / "failing.json"), decide=failing_rule)
    assert not failing.check("2026-10-11").passed and not failing.check("2026-10-11").passed
    assert len(failing_calls) == 44                                       # while suspended: re-tested on every beat, same day


def test_an_unreadable_record_is_a_suspension_and_the_next_check_reruns(tmp_path):
    store = self_test.SelfTestStore(tmp_path / "self_test.json")
    (tmp_path / "self_test.json").write_text("{not json", encoding="utf-8")
    held = store.read()
    assert held is not None and not held.passed and self_test.health_items(held)[0].klass is HealthClass.SECURITY
    assert self_test.SelfTest(store).check(TODAY).passed and store.read().passed


def test_the_suspension_is_a_health_item_on_blackbox_status(svc, monkeypatch, capsys):
    svc.beat("A", tester=self_test.SelfTest(decide=_one_wrong()))
    with svc.machines["A"]:
        items = curate.status_health_items(time.time())
        assert [item.klass for item in items] == [HealthClass.SECURITY] and "curator SUSPENDED" in items[0].message
        monkeypatch.setattr(cli.health, "gather", lambda *args, **kwargs: None)
        monkeypatch.setattr(cli.health, "operator_health", lambda inputs: [])
        cli._print_health(dataclasses.replace(CFG, context_graph_id=""), None, None, False)
        assert "[SECURITY] curator SUSPENDED: its self-test failed 1 of 22" in capsys.readouterr().out
        svc.beat("A")                                                     # a passing run lifts it
        assert curate.status_health_items(time.time()) == []


def test_an_undelivered_proposal_is_retried_each_beat_and_alarmed_on_the_third(svc):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    start = svc.inbox("B")
    first, second, third = (svc.beat("A", peers=[]) for _ in range(3))
    assert len(first.proposed) == 1
    for report, beats in ((first, 1), (second, 2)):
        assert any(f"reached no other curator yet (retrying next beat, {beats} of 3)" in e for e in report.errors)
        assert not any("ALARM" in e for e in report.errors)
    assert any("ALARM" in e and "for 3 beats" in e and "quorum is halted" in e for e in third.errors)
    with svc.machines["A"]:
        alarms = curate.status_health_items(time.time())
        assert [item.klass for item in alarms] == [HealthClass.ACTION] and first.proposed[0] in alarms[0].message
    assert svc.inbox("B") == start
    delivered = svc.beat("A")                                             # the peer is back: the SAME proposal arrives
    assert delivered.errors == () and svc.inbox("B") == start + 1
    with svc.machines["A"]:
        assert curate.status_health_items(time.time()) == []              # the alarm clears


def test_an_alarm_for_a_proposal_no_longer_retried_fades(tmp_path):
    ledger = transport.DeliveryLedger(tmp_path / "undelivered.json")
    for _ in range(3):
        ledger.failed("p1", now=1_000.0)
    assert [item.proposal_id for item in ledger.alarms(1_000.0)] == ["p1"]
    assert ledger.alarms(1_000.0 + transport.ALARM_FRESH_SECONDS + 1) == []
    assert transport.delivery_health_items(1_000.0, ledger)[0].klass is HealthClass.ACTION


# ------------------------------------------------------------------ SVC3: the dispute lane

FORM = {"identifier": DOMAIN, "party": "domain-owner", "reason": "wrong", "reply_to": "owner@login-paypa1.example"}
FILED = 1_800_000_000.0


class Disputes:
    """One curator's dispute intake on its own home: a fixed clock, a fresh key, a store, a signing log."""

    def __init__(self, tmp_path, *, per_hour=intake.SUBMISSIONS_PER_HOUR):
        self.key = Ed25519PrivateKey.generate()
        self.log = SigningLog(tmp_path / "signing_log.jsonl")
        self.ctx = CurateContext(cfg=CFG, client=None, environment=NETWORK, view=CuratorView(), sandbox=True,
                                 compiled=None, signing_log=self.log)
        self.store = intake.DisputeStore(tmp_path / "curate")
        self.intake = intake.DisputeIntake(self.ctx, key=lambda: self.key, store=self.store,
                                           bucket=TokenBucket(per_hour, 3600.0), clock=lambda: FILED)

    def file(self, **changed):
        answer = self.intake.submit({**FORM, **changed})
        assert answer.status == 202, answer
        return self.store.get(answer.body["dispute_id"])


@pytest.fixture
def lane(tmp_path):
    return Disputes(tmp_path)


def _looked_up(identifier, *statuses):
    item = disputes.lookup_item(intake.DisputeRecord("d", identifier, "domain-owner", "wrong", FILED, ""))
    return LookupResult(item, tuple(SourceVerdict(status, source=f"source-{n}",
                                                  reference_id="ref-1" if status is Lookup.FOUND else "")
                                    for n, status in enumerate(statuses)))


def test_a_dispute_becomes_a_signed_queue_item_in_lane_dispute_with_no_counted_reporter(lane):
    record = lane.file()
    payload = intake.verified_dispute_item(record.envelope, environment=NETWORK, curator_keys=[signing.public_key_hex(lane.key)])
    assert payload == {"dispute_id": record.dispute_id, "identifier": DOMAIN, "party": "domain-owner", "reason": "wrong",
                       "filed_at": str(int(FILED))}
    assert [(row.kind, row.action) for row in lane.log.rows()] == [(DISPUTE_INTAKE_STATEMENT, "sign")]   # through the choke point
    assert intake.verified_dispute_item(record.envelope, environment=NETWORK, curator_keys=["f" * 64]) is None
    assert intake.verified_dispute_item("not an envelope", environment=NETWORK, curator_keys=["f" * 64]) is None   # never raises
    assert intake.verified_dispute_item(record.envelope, environment="other-network",
                                        curator_keys=[signing.public_key_hex(lane.key)]) is None
    uncounted = {DOMAIN: {"stage": "reported", "counted": "0", "reporterCount": 1}}
    assert queue.delta_view(uncounted, set()).new == ()                                     # without the dispute: no lane
    view = queue.delta_view(uncounted, set(), publicly_disputed=lane.store.open_identifiers())
    assert [(item.identifier, item.lane, item.disputed) for item in view.new] == [(DOMAIN, queue.Lane.DISPUTE, True)]
    assert queue.Lane.DISPUTE is queue.Lane.DISPUTES_AND_REVOCATIONS and view.unlisted_only == ()


def test_a_dispute_against_a_verified_listing_with_no_community_report_reaches_the_lane(lane):
    lane.file()
    view = queue.delta_view({}, {DOMAIN}, publicly_disputed=lane.store.open_identifiers())
    assert [(item.identifier, item.lane, item.reporters) for item in view.new] == [(DOMAIN, queue.Lane.DISPUTE, 0)]
    assert view.already_verified == ()


def test_the_signed_item_and_the_store_keep_no_personal_data_and_the_reply_address_is_erased_on_close(lane, tmp_path):
    record = lane.file()
    assert FORM["reply_to"] not in record.envelope and FORM["reply_to"] not in (tmp_path / "curate" / "disputes.json").read_text()
    contacts = tmp_path / "curate" / "dispute_contacts.json"
    assert lane.store.contact(record.dispute_id) == FORM["reply_to"] and (contacts.stat().st_mode & 0o777) == 0o600
    assert lane.store.close(record.dispute_id, "upheld", now=FILED + 60) is not None
    assert lane.store.contact(record.dispute_id) == "" and FORM["reply_to"] not in contacts.read_text()
    assert lane.store.close(record.dispute_id, "upheld", now=FILED + 61) is None              # closes once


@pytest.mark.parametrize("body, why", [
    ("not an object", "JSON object"),
    ({**FORM, "name": "Jane Doe"}, "fields not allowed"),                                     # nothing beyond the form
    ({k: v for k, v in FORM.items() if k != "reply_to"}, "reply_to is required"),
    ({**FORM, "identifier": ""}, "identifier is required"),
    ({**FORM, "identifier": 7}, "identifier is required"),
    ({**FORM, "identifier": "ioc:domain:a b"}, "single token"),
    ({**FORM, "identifier": "ioc:domain:evil‮.example"}, "single token"),               # a bidi override
    ({**FORM, "identifier": "somebody@example.com"}, "threat identifier"),
    ({**FORM, "party": "lawyer"}, "party must be one of"),
    ({**FORM, "reason": "tolerable"}, "reason must be one of"),                               # a node's reason, not a party's
    ({**FORM, "reply_to": "not-an-address"}, "e-mail"),
    ({**FORM, "reply_to": "a@b.example\r\nBcc: x@y.example"}, "e-mail"),
    ({**FORM, "reply_to": "a" * 250 + "@b.example"}, "e-mail"),
])
def test_the_endpoint_validates_every_field_on_the_server(lane, body, why):
    answer = lane.intake.submit(body)
    assert answer.status == 400 and why in answer.body["error"]
    assert lane.store.all() == [] and lane.log.rows() == []                                    # nothing signed, nothing kept


def test_a_second_dispute_on_an_open_listing_folds_into_the_first_and_keeps_no_second_address(lane):
    first = lane.file()
    again = lane.intake.submit({**FORM, "reply_to": "someone-else@example.org"})
    assert (again.status, again.body["dispute_id"], again.body["state"]) == (202, first.dispute_id, "already open")
    assert len(lane.store.all()) == 1 and lane.store.contact(first.dispute_id) == FORM["reply_to"]


def test_simultaneous_disputes_on_one_listing_open_it_once_and_keep_one_address(lane):   # FIX-0091
    """Eight senders reach the endpoint at the same instant with the same identifier:
    ONE dispute opens, ONE reply address is kept, the other seven are told it is
    already open — the check, the signature and the store write are one step."""
    senders, gate, answers = 8, threading.Barrier(8), []

    def slow_key():                      # signing takes time; every sender has passed the "already open?" check by then
        time.sleep(0.02)
        return lane.key
    lane.intake = intake.DisputeIntake(lane.ctx, key=slow_key, store=lane.store, clock=lambda: FILED)

    def send(n):
        gate.wait()
        answers.append(lane.intake.submit({**FORM, "reply_to": f"sender{n}@example.org"}))
    threads = [threading.Thread(target=send, args=(n,)) for n in range(senders)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(answer.body["state"] for answer in answers) == ["already open"] * 7 + ["open"]
    assert {answer.status for answer in answers} == {202} and len({answer.body["dispute_id"] for answer in answers}) == 1
    (record,) = lane.store.all()
    assert sum(answer.body["state"] == "open" for answer in answers) == 1
    kept = json.loads((lane.store._contacts).read_text())
    assert list(kept) == [record.dispute_id] and len(lane.log.rows()) == 1          # one address kept, one signature made


def test_the_endpoint_is_rate_limited_and_refuses_when_the_queue_is_full(tmp_path, monkeypatch):
    limited = Disputes(tmp_path / "limited", per_hour=1)
    limited.file()
    assert limited.intake.submit({**FORM, "identifier": IP}).status == 429
    full = Disputes(tmp_path / "full")
    monkeypatch.setattr(intake, "MAX_OPEN_DISPUTES", 1)
    full.file()
    assert full.intake.submit({**FORM, "identifier": IP}).status == 503


def test_a_dispute_that_cannot_be_signed_is_refused_not_kept(lane):
    def broken():
        raise ValueError("no key")
    lane.intake = intake.DisputeIntake(lane.ctx, key=broken, store=lane.store, clock=lambda: FILED)
    answer = lane.intake.submit(FORM)
    assert answer.status == 503 and "no key" not in answer.body["error"] and lane.store.all() == []


def test_the_public_reasons_are_a_nodes_false_positive_words():
    assert set(intake.PUBLIC_DISPUTE_REASONS) <= set(constants.FALSE_POSITIVE_REASONS)


def test_a_rerun_that_finds_no_source_and_a_clean_lab_yields_a_correction_request(lane):
    record = lane.file()
    facts = disputes.facts_from_lookup(_looked_up(DOMAIN, Lookup.CLEAN, Lookup.NOT_APPLICABLE), citable_sources={"source-0"},
                                       lab=(CLEAN_RUN,))
    outcome = disputes.rerun(record, facts)
    assert outcome.action is disputes.DisputeAction.RETRACT and outcome.decision.verdict is Verdict.REJECTED
    assert outcome.correction == disputes.CorrectionRequest(DOMAIN, f"dispute upheld: {outcome.decision.reason}",
                                                            f"dispute:{record.dispute_id}", FILED + 72 * 3600)
    assert outcome.row()["disputeRoute"] == DISPUTE_ROUTE == "https://blackboxcommand.com/dispute"


@pytest.mark.parametrize("statuses, lab, action", [
    ((Lookup.FOUND,), (), disputes.DisputeAction.UPHOLD),                       # a citable source still lists it
    ((Lookup.UNAVAILABLE, Lookup.CLEAN), (CLEAN_RUN,), disputes.DisputeAction.PERSON),   # could not tell is never wrong
    ((Lookup.CLEAN,), (), disputes.DisputeAction.PERSON),                       # the lab never ran
    ((Lookup.NOT_APPLICABLE,), (CLEAN_RUN,), disputes.DisputeAction.PERSON),    # no source answered at all
])
def test_a_rerun_retracts_only_on_a_definite_clean_answer(lane, statuses, lab, action):
    outcome = disputes.rerun(lane.file(), disputes.facts_from_lookup(_looked_up(DOMAIN, *statuses), citable_sources={"source-0"},
                                                                     lab=lab))
    assert outcome.action is action and outcome.correction is None
    assert outcome.row()["disputeRoute"] == DISPUTE_ROUTE                       # every verdict row names its route


def test_a_listing_found_only_by_a_look_up_only_source_is_not_wrong_and_not_cited():
    facts = disputes.facts_from_lookup(_looked_up(DOMAIN, Lookup.FOUND), citable_sources=set(), lab=(CLEAN_RUN,))
    assert facts.citable_listing == "" and not facts.sources_clean


@pytest.mark.parametrize("fabricated, strikes", [(True, 1), (False, 0)])
def test_a_fabricated_report_yields_one_strike_and_an_honest_one_none(lane, tmp_path, fabricated, strikes):
    ledger = reputation.ReputationLedger(tmp_path / "ledger.json")
    reporter = Reporter("0xa").author
    record = lane.file()
    outcome = disputes.rerun(record, disputes.facts_from_lookup(_looked_up(DOMAIN, Lookup.CLEAN), citable_sources=set(),
                                                                lab=(CLEAN_RUN,)))
    struck = disputes.settle(lane.store, ledger, outcome, reporters=[reporter, reporter], fabricated=fabricated, today=TODAY,
                             now=FILED + 3600)
    assert struck == ((reporter,) if fabricated else ())
    again = disputes.settle(lane.store, ledger, outcome, reporters=[reporter], fabricated=fabricated, today=TODAY,
                            now=FILED + 7200)
    assert again == () and ledger.standing(reporter).strikes == strikes                     # one strike, never two
    assert lane.store.get(record.dispute_id).outcome == "retract" and lane.store.contact(record.dispute_id) == ""


def test_an_upheld_listing_strikes_nobody_even_if_called_fabricated(lane, tmp_path):
    ledger = reputation.ReputationLedger(tmp_path / "ledger.json")
    reporter = Reporter("0xa").author
    found = disputes.facts_from_lookup(_looked_up(DOMAIN, Lookup.FOUND), citable_sources={"source-0"})
    outcome = disputes.rerun(lane.file(), found)
    assert disputes.settle(lane.store, ledger, outcome, reporters=[reporter], fabricated=True, today=TODAY, now=FILED) == ()
    assert ledger.standing(reporter).strikes == 0


def test_a_dispute_a_person_must_decide_cannot_be_settled_from_the_rerun(lane, tmp_path):
    outcome = disputes.rerun(lane.file(), VerdictFacts())
    with pytest.raises(ValueError):
        disputes.settle(lane.store, reputation.ReputationLedger(tmp_path / "l.json"), outcome, reporters=[], fabricated=False,
                        today=TODAY, now=FILED)


def test_the_72_hour_deadline_is_a_health_alarm_when_missed(lane):
    record = lane.file()
    deadline = FILED + 72 * 3600
    assert disputes.dispute_health_items(deadline, lane.store) == []
    items = disputes.dispute_health_items(deadline + 1, lane.store)
    assert [(item.klass, record.dispute_id in item.message, DOMAIN in item.message) for item in items] == [
        (HealthClass.ACTION, True, True)]
    lane.store.close(record.dispute_id, "retract", now=deadline + 2)
    assert disputes.dispute_health_items(deadline + 3, lane.store) == []                    # a closed dispute alarms no more


# ------------------------------------------------------------------ SVC4: one line per new step, the --publisher flag

#: Beat.run's order: the C9 steps with the trust-and-threat-lab steps on their own lines between them.
STEP_ORDER = ["heartbeat", "read", "cosign", "look up", "lab collect", "first signatures", "lab submit", "credit",
              "ladder", "keep alive", "publish batch", "withdrawal", "watch"]
NEW_STEPS = ["look_up", "lab_collect", "lab_submit", "publish_batch", "withdrawal", "watch"]
LAB_IMAGE = "a" * 64
LAB_PEER = "12D3KooW" + "A" * 44


class Recording(ServiceSteps):
    """The new steps, each recording that it ran; *failing* steps raise instead."""

    def __init__(self, order, failing=()):
        super().__init__()
        self.order, self.failing = order, set(failing)
        for name in NEW_STEPS:
            setattr(self, name, self._recorder(name))

    def _recorder(self, name):
        def step(run):
            self.order.append(name.replace("_", " "))
            if name in self.failing:
                raise RuntimeError(f"{name} broke")
        step.__name__ = name
        return step


def _recorded_beat(svc, monkeypatch, failing=()):
    order = []
    for name in ("heartbeat", "read", "cosign", "first_signatures", "credit", "ladder", "keep_alive"):
        monkeypatch.setattr(Beat, f"_{name}", lambda self, run, name=name: order.append(name.replace("_", " ")))
    machine = svc.machines["A"]
    with machine:
        report = Beat(lambda interest: svc.ctx(machine, interest), peers=["B"], steps=Recording(order, failing)).run()
    return order, report


def test_every_new_step_runs_in_its_place_in_the_beat(svc, monkeypatch):
    order, report = _recorded_beat(svc, monkeypatch)
    assert order == STEP_ORDER and report.errors == ()


def test_every_new_step_is_one_line_of_beat_run():
    import inspect
    source = inspect.getsource(Beat.run).splitlines()
    lines = [[number for number, line in enumerate(source) if f"more.{name}" in line] for name in NEW_STEPS]
    assert all(len(found) == 1 for found in lines), lines              # one line each, none repeated
    assert [found[0] for found in lines] == sorted(found[0] for found in lines)


def test_a_failing_new_step_never_stops_the_beat(svc, monkeypatch):
    order, report = _recorded_beat(svc, monkeypatch, failing={"look_up", "publish_batch"})
    assert order == STEP_ORDER                                          # every later step still ran
    assert report.errors == ("look up: look_up broke", "publish batch: publish_batch broke")


class Publisher:
    """Step 8's stand-in: records the context it ran with and answers *action*."""

    def __init__(self, action="published", note=""):
        self.contexts, self.action, self.note = [], action, note

    def run(self, ctx):
        self.contexts.append(ctx)
        return curate.publishing.BatchRunReport(self.action, "b-1", entries=3, note=self.note)


def test_step_8_runs_only_on_the_node_started_with_publisher(svc):
    publisher = Publisher()
    report = svc.beat("A", publisher=publisher)
    assert len(publisher.contexts) == 1 and report.batch == "published" and "batch published" in report.summary()
    plain = svc.beat("B")
    assert plain.batch == "" and "batch" not in plain.summary()


def test_step_8_publishes_nothing_while_this_node_may_not_sign(tmp_path, monkeypatch):
    svc = Service(tmp_path, monkeypatch, accepted="B")                  # A never accepted the automation policy
    publisher = Publisher()
    report = svc.beat("A", publisher=publisher)
    assert publisher.contexts == [] and report.batch == "held" and not report.may_sign


def test_a_batch_that_could_not_tell_is_a_step_error_and_the_beat_goes_on(svc):
    report = svc.beat("A", publisher=Publisher("could-not-tell", "the live verified lookup is not ready"))
    assert report.errors == ("publish batch: could-not-tell (the live verified lookup is not ready)",)
    assert report.heartbeat == "published"


def test_the_publisher_flag_decides_whether_a_node_builds_the_batch_publisher(monkeypatch):
    from plugins.blackbox.curate.service import steps as steps_module
    monkeypatch.setattr(steps_module, "SOURCES", ())                    # no outside source in this test
    built = {}
    monkeypatch.setattr(service.commands, "Beat", lambda context, peers, steps: built.setdefault("steps", steps)
                        or pytest.fail("no beat"))
    with pytest.raises(AttributeError):                                 # the stand-in has no run(): stop after building
        service.run_command(lambda interest: None, peers=[], interval=60, once=True, publisher=True)
    assert isinstance(built["steps"]._publisher, curate.publishing.BatchPublisher)
    built.clear()
    with pytest.raises(AttributeError):
        service.run_command(lambda interest: None, peers=[], interval=60, once=True)
    assert built["steps"]._publisher is None


def test_the_run_verb_hands_the_publisher_flag_to_the_service(monkeypatch):
    import argparse
    seen = {}
    monkeypatch.setattr(service.commands, "run_command", lambda context, **kw: seen.update(kw) or 0)
    parser = argparse.ArgumentParser(prog="blackbox")
    cli.setup_cli(parser)
    args = parser.parse_args(["curate", "run", "--publisher", "--peer", "x", "--once"])
    assert args.func(args) == 0
    assert seen == {"peers": ["x"], "interval": 300.0, "once": True, "publisher": True}
    args = parser.parse_args(["curate", "run", "--once"])
    args.func(args)
    assert seen["publisher"] is False


def test_the_first_signatures_read_the_budgeted_look_ups_never_one_osv_call_per_item(svc, monkeypatch):
    from plugins.blackbox.curate.service import evidence as evidence_module
    monkeypatch.setattr(evidence_module, "own_check", lambda *a, **k: pytest.fail("the beat called OSV for an item"))
    threats = [f"dep:npm:evil-{n}@1.0.0" for n in range(3)]
    for threat in threats:
        svc.report(threat)
    asked, cosign_asked = [], []

    def source_answer(identifier):
        asked.append(identifier)
        return FOUND

    machine = svc.machines["A"]
    with machine:
        steps = ServiceSteps(sources=node_sources(source_answer), lookup_budget=LookupBudget(items_per_beat=1))
        report = Beat(lambda interest: svc.ctx(machine, interest), peers=["B", "C"],
                      lookup=lambda identifier: cosign_asked.append(identifier) or FOUND, steps=steps).run()
    assert len(asked) == 1 and cosign_asked == []                       # one look-up: the budget's; none per item
    assert report.looked_up == 1 and len(report.proposed) == 1          # only the looked-up item is confirmed
    assert not any(threat in asked for threat in threats if threat not in asked)


def test_an_item_no_look_up_reached_is_could_not_tell_never_clean(svc):
    from plugins.blackbox.curate.service.evidence import NOT_LOOKED_UP
    assert NOT_LOOKED_UP.status is Lookup.UNAVAILABLE
    svc.compiled["A"] = Corroborated(PKG)
    report = svc.beat("A", lookup_budget=LookupBudget(items_per_beat=0))
    assert report.looked_up == 0 and report.published == (f"in-review {PKG}",)   # acknowledged, never deferred unasked


class Lab:
    """The lab controller's stand-in: a real job store; ``poll`` counts the collects."""

    def __init__(self, path):
        from plugins.blackbox.curate.lab import LabJobStore
        self.store, self.polls = LabJobStore(path), 0
        self.submit = self.store.request

    def poll(self):
        self.polls += 1


def _lab(tmp_path, lab, levels=(1, 2)):
    from plugins.blackbox.curate.lab.trigger import LabRequests, LabSetup
    from plugins.blackbox.curate.service.steps import LabWiring
    return LabWiring(lambda ctx: lab, LabSetup({level: LAB_IMAGE for level in levels}, requested_by=LAB_PEER),
                     LabRequests(tmp_path / "requests.jsonl"))


def test_the_lab_collects_every_beat_and_submits_what_a_partner_reported_and_a_curator_requested(svc, tmp_path):
    bob = Reporter("0xb")
    svc.team.two_key(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob, **{"class": "partner", "org": "acme"}))
    svc.report(IP, reporter=bob)
    lab = Lab(tmp_path / "jobs.jsonl")
    wiring = _lab(tmp_path, lab)
    first = svc.beat("A", lab=wiring)
    assert lab.polls == 1 and first.lab_jobs == 0                       # one partner cluster, no request: no job
    wiring.requests.record(IP, code="1a2b3c4d")                          # the curator's typed request (a human act)
    second = svc.beat("A", lab=wiring)
    assert lab.polls == 2 and second.lab_jobs == 1
    assert [(record.job.identifier, record.job.level) for record in lab.store.records()] == [(IP, 1)]


def test_the_lab_never_runs_what_a_source_lists(svc, tmp_path):
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    lab = Lab(tmp_path / "jobs.jsonl")
    wiring = _lab(tmp_path, lab)
    wiring.requests.record(PKG, code="1a2b3c4d")
    report = svc.beat("A", lab=wiring)
    assert report.lab_jobs == 0 and lab.store.records() == []


def test_level_3_is_never_sent_to_a_lab_host(tmp_path):
    with pytest.raises(ValueError, match="urlscan"):
        _lab(tmp_path, Lab(tmp_path / "jobs.jsonl"), levels=(1, 3))


def _confirmed_and_withdrawn(svc, tmp_path, **propose):
    """PKG confirmed by A and B citing its advisory; a watcher whose OSV re-check says it was withdrawn."""
    svc.report(PKG)
    svc.answers[PKG] = FOUND
    svc.beat("A")
    svc.beat("B")                                                       # confirmed, citing advisory:MAL-2026-1
    rechecked = []
    watcher = WithdrawalWatcher({"osv": lambda c: rechecked.append((c.identifier, c.reference_id)) or Lookup.CLEAN},
                                state_path=tmp_path / "withdrawal_state.json", **propose)
    return watcher, rechecked


def test_the_weekly_withdrawal_step_revokes_a_confirmation_whose_advisory_was_withdrawn(svc, tmp_path):
    revocations = []

    def propose(ctx, store, identifier, evidence):   # the signing itself is SRC4's (test_blackbox_sources.py)
        revocations.append((identifier, evidence))
        return dataclasses.make_dataclass("Signed", ["id"])("rev-1")

    watcher, rechecked = _confirmed_and_withdrawn(svc, tmp_path, propose=propose)
    report = svc.beat("A", withdrawal=watcher)
    assert rechecked == [(PKG, "MAL-2026-1")] and revocations == [(PKG, "withdrawn:osv:MAL-2026-1")]
    assert len(report.proposed) == 1 and report.errors == ()
    assert svc.beat("A", withdrawal=watcher).proposed == () and len(rechecked) == 1     # once a week


def test_the_withdrawal_step_waits_while_this_node_may_not_sign(tmp_path, monkeypatch):
    svc = Service(tmp_path, monkeypatch, accepted="B")
    watcher = WithdrawalWatcher({}, state_path=tmp_path / "withdrawal_state.json")
    svc.beat("A", withdrawal=watcher)
    assert watcher.due()                                                # its week did not start


class Sink:
    def __init__(self):
        self.alarms, self.metrics = [], []

    def notify(self, event):
        return True

    def notify_alarm(self, item):
        self.alarms.append(item)
        return True

    def notify_metrics(self, record):
        self.metrics.append(record)
        return True


def test_the_watch_step_posts_the_dead_man_beat_once_a_day_and_metrics_without_a_publish_ledger(svc, tmp_path, monkeypatch):
    from plugins.blackbox.curate.service import steps as steps_module
    sink = Sink()
    monkeypatch.setattr(steps_module, "SOURCES", ())
    monkeypatch.setattr(curate.watch, "node_sink", lambda: sink)       # this node's OWN sink
    steps = ServiceSteps.for_node(publisher=False, beat_seconds=300)
    machine = svc.machines["A"]
    with machine:
        first = Beat(lambda interest: svc.ctx(machine, interest), peers=["B"], steps=steps).run()
        second = Beat(lambda interest: svc.ctx(machine, interest), peers=["B"], steps=steps).run()
    beats = [item for item in sink.alarms if item.message.startswith("watcher beat")]
    assert len(beats) == 1 and first.alarms >= 1 and second.alarms == 0
    assert len(sink.metrics) == 1 and sink.metrics[0].publish_failures is None   # "unavailable", never a confident 0


def test_a_node_with_no_alarm_sink_says_so_every_beat(svc, monkeypatch):
    def no_sink():
        raise curate.watch.SinkCredentialError("no readable alarm_sink.json in this node's curate home")
    report = svc.beat("A", alarms=intake.AlarmWatcher(), sink=no_sink)
    assert report.errors == ("watch: no readable alarm_sink.json in this node's curate home",)
    assert report.heartbeat == "published"


def test_cited_confirmations_take_only_advisory_evidence():
    from plugins.blackbox.community import CuratorView
    from plugins.blackbox.community.statements.curator_statements import CuratorRecord
    from plugins.blackbox.curate.service.steps import cited_confirmations
    view = CuratorView(verdicts={
        PKG: CuratorRecord(Kind.CONFIRMATION, PKG, 1, TODAY, (("evidence", "advisory:MAL-1"),), frozenset()),
        IP: CuratorRecord(Kind.CONFIRMATION, IP, 1, TODAY, (("evidence", "reproduced:" + "b" * 64),), frozenset()),
        "dep:npm:x@1": CuratorRecord(Kind.DEFERRAL, "dep:npm:x@1", 1, TODAY, (), frozenset())})
    assert [(c.identifier, c.source, c.reference_id, c.tested_day) for c in cited_confirmations(view)] == [
        (PKG, "osv", "MAL-1", TODAY)]



def test_the_watch_step_delivers_what_the_ledger_checks_raise_once(svc, tmp_path):
    from plugins.blackbox.kernel.health import HealthItem
    sink, seen = Sink(), []

    def unexpected_asset(ctx, now):   # a W2 comparison: an asset neither the ledger nor the co-sign log explains
        seen.append(ctx)
        return [HealthItem("curator", HealthClass.SECURITY, "unexpected verified asset did:dkg:x/1", "check the wallet")]

    steps = dict(alarms=intake.AlarmWatcher(tmp_path / "alarms_seen.json"), sink=lambda: sink, ledger_checks=[unexpected_asset])
    svc.beat("A", **steps)
    svc.beat("A", **steps)
    assert len(seen) == 2 and [item.message for item in sink.alarms].count("unexpected verified asset did:dkg:x/1") == 1
